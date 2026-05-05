# Secure Vector Trino Plugin

## Overview
The [Secure Vector Trino Plugin](../plugin/secure-vector-trino/src/main/java/secure/vector/trino) extends [Trino's](https://trino.io/) [PostgreSqlPlugin](https://github.com/trinodb/trino/tree/479/plugin/trino-postgresql/src/main/java/io/trino/plugin/postgresql) with Virtru's secure vector implementation. The plugin is built using Trino's [Plugin framework](https://trino.io/docs/current/installation/plugins.html) and inherits all of the existing JDBC/PostgreSQL Trino plugin capabilities with secure vector logic added in.

Secure Vector Trino can be deployed wrapped in the [TDF Trino Plugin](./index.md) to add TDF and ABAC enforcement.

### Key Features
- **Database Support**: PostgreSQL/pgvector for performant secure vector embedding storage and search
- **Embedding Protection**: Transparently transforms plaintext embeddings to secure representation on insertion
- **Custom Distance Function**: Enables semantic distance search against secure embeddings
- **Algorithm Masking**: Trino and clients have no visibility into the actual secure embeddings stored in PostgreSQL, and instead interact only with plaintext embeddings

## Setup and Configuration

### PostgreSQL with pgvector
Secure Vector Trino expects the data source to be PostgreSQL with the [pgvector extension](https://github.com/pgvector/pgvector?tab=readme-ov-file). The database must be up and running before the Trino engine starts because Secure Vector Trino sets up and reads from its own metadata cache tables on start-up.

### Connector Configuration
Any configuration parameters prefixed with `secure.vector` are specific to this connector. The remaining configure the underlying PostgreSQL functionality.

| Property name                        | Description                                                                                                                                        |
|--------------------------------------|----------------------------------------------------------------------------------------------------------------------------------------------------| 
| connector.name                       | Name of the connector, required to be `securevector`                                                                                               |
| connection-url                       | JDBC connection URL for the PostgreSQL database                                                                                                    |
| connection-user                      | Username for the PostgreSQL database connection, must have write access to the PostgreSQL instance                                                 |
| connection-password                  | Password for the PostgreSQL database connection                                                                                                    |
| postgresql.array-mapping             | Determines how trino handles array columns - must be set to `AS_ARRAY`                                                                             |
| complex-expression-pushdown.enabled  | Determines whether the connector attempts to pushdown complex query expressions to the database - must be set to `true` (default)                  |
| secure.vector.key                    | Key for secure vector conversion, pass as an environment variable secret                                                                           |
| secure.vector.catalog                | Must match the `catalog` portion of your `catalog.properties` filename                                                                             |

### Key Rotation
The `secure.vector.key` controls the secure embedding conversion process. Rotating to a new key requires re-inserting plaintext embeddings to generate new secure embeddings.

## Usage Examples
### Set up PostgreSQL/pgvector
PostgreSQL/pgvector configuration outside of Trino is preferred, but commands can be sent to the underlying database like this.
```sql
CALL system.execute(query => 'CREATE EXTENSION IF NOT EXISTS vector');
```

### Create a Table
Designate secure embedding columns when creating a table - the column must be typed as `array(double)` and include the column property `base_dimension` to indicate the plaintext embedding dimension. Secure embedding column names must be unique across tables within the same catalog. Duplicate secure embedding column names allowed across different catalogs.
```sql
CREATE TABLE secure_vector_table (id bigint, document varchar, embedding array(double) WITH (base_dimension=3));
```

### Insert Embeddings
Send plaintext embeddings and the plugin will store them in secure form
```sql
INSERT INTO secure_vector_table (id, document, embedding) VALUES (1, 'hello', ARRAY[0.1234, 0.4567, 0.7891]);
```

### Create Table As Select (CTAS)
`CREATE TABLE AS SELECT` is not supported on secure vector tables. CTAS bypasses the column validation and SQL rewriting that `CREATE TABLE` applies to embedding columns, and the `SELECT` side of a CTAS returns masked (NULL) embedding values — so the destination table would always contain null embeddings regardless of intent. Create the table with `CREATE TABLE` first, then use `INSERT`.

### Query Embeddings
Direct queries will return masked embeddings
```sql
SELECT * FROM secure_vector_table;

id | document | embedding
1  | hello    | [null]
```

Distance Search (values range [0,1] - 0 means perfect match)
```sql
SELECT id, secure_vector_distance(embedding, ARRAY[0.1234, 0.4567, 0.7891]) as distance FROM secure_vector_table;

id | distance
1  | 0
```

#### A Special Note about Secure Vector Distance Search
Secure Vector Trino rewrites the `secure_vector_distance` function to convert query vectors to secure representations and then use pgvector's hamming distance operator for vector comparison. This means the logic must be pushed down to the underlying pgvector datasource in order to work and take advantage of pgvector comparison optimizations. Depending on the query pattern, Trino's planner may or may not perform pushdown for this function. If Trino does not perform pushdown and instead attempts to call the `secure_vector_distance` function itself, the following error will appear - `direct calls not supported, calls to this function should be pushed down`.

Secure Vector Trino purposefully does not allow equality comparisons (= (equal), <> (not equal), >= (greater than or equal), <= (less than or equal)) with the output of `secure_vector_distance` because of floating point imprecision. In those cases, the error would be expected. Other numeric comparisons and operations are allowed.

Otherwise, the only known limitation is in `JOIN` queries that include `secure_vector_distance`. This is not a bug - this is a fundamental limitation in Trino's architecture given it must support `JOIN` operations across tables and catalogs.

```sql
SELECT e.*, b.empl_id, b.biography, secure_vector_distance(b.embedding, ARRAY[0.1234, 0.4567, 0.7891]) as distance
FROM tdf_psql.public.employees as e
JOIN tdf_securevector.public.background AS b
ON e.empl_id = b.empl_id
```

In this query, Trino scans each table independently, pulls raw data into its coordinator, performs the `JOIN` in its memory, and evaluates the projections on the resulting columns after the `JOIN` - calling `secure_vector_distance` directly.

Use a Common Table Expression (CTE) query like the following instead to ensure the `secure_vector_distance` function gets pushed down on the single table inside the `WITH` clause -

```sql
WITH distances AS (
  SELECT
    empl_id,
    biography,
    secure_vector_distance(embedding, ARRAY[0.1234, 0.4567, 0.7891]) as distance
  FROM tdf_securevector.public.background
)
SELECT e.*, d.empl_id, d.biography, d.distance
FROM tdf_psql.public.employees AS e
JOIN distances AS d ON e.empl_id = d.empl_id
```


### Indexing
Secure Vector Trino supports any index pgvector offers (currently HNSW or IVFFlat). Indexes must be built over secure embedding columns using the `bit_hamming_ops` operator. `secure_vector_distance` queries must combine `ORDER BY` and `LIMIT` clauses to ensure index usage - a standard pgvector query pattern and not any restriction created by Secure Vector Trino.
```sql
SELECT document, secure_vector_distance(embedding, ARRAY[0.1234, 0.4567, 0.7891]) as distance FROM secure_vector_table ORDER BY distance LIMIT 5;
```

### Cache Fixes
Secure Vector Trino maintains a cache in the PostgreSQL database with metadata required for secure embedding conversions and queries. The plugin updates the cache during `CREATE TABLE` and `DROP TABLE` commands. If a cache update fails, a Trino exception will be thrown with a detailed error message containing instructions on how to fix the cache. These steps should only be taken in these special circumstances.

To fix a cache error from `CREATE TABLE` -
```sql
SET SESSION <catalog>.cache_fix='create:<columnName>:<baseDimension>';
CREATE TABLE IF NOT EXISTS <tableName> <remaining CREATE TABLE that caused the error>;
RESET SESSION <catalog>.cache_fix;
```

To fix a cache error from `DROP TABLE` -
```sql
SET SESSION <catalog>.cache_fix='drop';
DROP TABLE IF EXISTS <tableName>;
RESET SESSION <catalog>.cache_fix;
```