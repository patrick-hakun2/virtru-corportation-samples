# Data Protection: Policy, Encryption, and Access Control

This document explains how TDF Trino protects data at rest and controls access at query time. It covers how policy is assigned during writes, how rows are filtered and columns are decrypted (or not) during reads, how authorization is enforced on data modification, and how each combination of user entitlements affects what a user sees.

For connector setup and configuration, see [index.md](./index.md).

---

## Concepts

### TDF Columns

Any column prefixed with `_tdf_` in the `CREATE TABLE` statement is a **TDF column**. TDF columns must be declared as `VARBINARY`. Data written to these columns is encrypted at rest using NanoTDF.

Users interact with TDF columns **without the prefix** — TDF Trino strips `_tdf_` automatically. A column created as `_tdf_name` appears as `name` in `SHOW COLUMNS`, `SELECT`, and `INSERT` statements.

### Attributes

Attributes are the building blocks of access control. Each attribute is a fully-qualified name (FQN) in the form:

```
https://<namespace>/attr/<attribute>/value/<value>
```

For example: `https://example.com/attr/clearance/value/secret`

Attributes are assigned to **data** (via policy) and to **users** (via the platform's authorization service). Access decisions compare the two.

### Actions

Each user-attribute association includes one or more **actions** that define what the user can do with data protected by that attribute:

| Action    | Default name | Purpose                                                              |
|-----------|-------------|----------------------------------------------------------------------|
| `view`    | `read`      | Allows the user to see that a row exists and to view all columns     |
| `decrypt` | `decrypt`   | Allows the user to decrypt TDF column values back to plaintext       |
| `update`  | `update`    | Required (with `view`) to modify a row's column values via MERGE UPDATE |
| `delete`  | `delete`    | Required (with `view`) to delete a row via MERGE DELETE              |

Action names are configurable via `tdf.action.view`, `tdf.action.decrypt`, `tdf.action.update`, and `tdf.action.delete` in the connector properties.

### Policy Column

TDF Trino automatically adds a `tdf_policy` column to every table it manages. This column stores a JSON object that captures the access control policy for each row. It is populated transparently on write and used internally for row filtering and authorization on read. It will be returned in a `SELECT *` query but should not be written to directly outside of the supported write mechanisms.

The policy column also contains a `policy_tag` field — an HMAC-SHA256 signature computed over the canonical policy content at write time. On every read (SELECT and MERGE target scan), TDF Trino verifies this signature. Any row whose `policy_tag` does not match fails the query with an error, preventing tampered or externally modified policy rows from being served.

---

## Write Path: How Data Is Protected on INSERT

When a row is inserted, TDF Trino:

1. **Resolves policy** for each TDF column and for the row's non-TDF columns
2. **Encrypts** each TDF column value into a NanoTDF using the resolved attributes or passes through a provided NanoTDF while extracting its attributes for the policy column
3. **Populates the policy column** with a JSON summary of all attribute groups

### Policy Resolution

Policy tells TDF Trino which attributes to protect each cell with. It is resolved per-cell using a priority chain — the first source that provides attributes wins:

| Priority | Source | Scope | How to set |
|----------|--------|-------|------------|
| 1 (highest) | NanoTDF header | Per-cell | Client sends a pre-encrypted NanoTDF as the cell value |
| 2 | `tdf_policy` column in INSERT | Per-row or per-column | Include `tdf_policy` as a column in the INSERT values |
| 3 | `tdf_data_attributes` session property | Per-row or per-column | `SET SESSION <catalog>.tdf_data_attributes = '...'` |
| 4 (lowest) | `tdf.default-data-attributes` config | Per-catalog | Set in the connector `.properties` file |

If no policy can be resolved for a column, the INSERT fails with an error.

### Policy Specification Formats

Policy can be specified at **row level** (all TDF columns share the same attributes) or at **column level** (each TDF column gets its own attribute set).

#### Row-Level Policy

All TDF columns in the row receive the same attributes.

**As a JSON array** (in `tdf_policy` column value):
```json
["https://example.com/attr/clearance/value/secret", "https://example.com/attr/department/value/engineering"]
```

**As a comma-separated string** (in session property or config):
```
https://example.com/attr/clearance/value/secret,https://example.com/attr/department/value/engineering
```

#### Column-Level Policy

Each TDF column can have different attributes. Non-TDF columns are covered by `default_policy`.

**As a JSON object** (in `tdf_policy` column value or session property):
```json
{
  "name": ["https://example.com/attr/clearance/value/secret"],
  "salary": ["https://example.com/attr/department/value/engineering"],
  "default_policy": ["https://example.com/attr/clearance/value/public"]
}
```

Keys are TDF column names (without the `_tdf_` prefix). The special key `default_policy` covers non-TDF columns.

#### Partial Column-Level with Fallback

Column-level policy can specify only some columns. Unspecified TDF columns fall back to the next source in the priority chain. For example, if the per-row policy sets `name` but not `salary`, the session property or config fills in `salary`.

### What Gets Stored

Regardless of input format, the policy column always stores a normalized JSON structure:

```json
{
  "tdf_policies": [["attr1", "attr2"], ["attr3"]],
  "default_policy": ["attr4", "attr5"],
  "policy_tag": "<HMAC-SHA256 base64>"
}
```

| Field | Contents |
|-------|----------|
| `tdf_policies` | Array of attribute groups — one group per distinct set of attributes used across TDF columns. A user must match **at least one** group. |
| `default_policy` | Single attribute array covering non-TDF columns. Empty (`[]`) if the table has only TDF columns. |
| `policy_tag` | HMAC-SHA256 signature over the canonical policy content. Computed on write; verified on every read. Do not modify this field. |

### Write Examples

#### Example 1: Simple row-level policy via session property

```sql
-- Set policy for all TDF columns in this session
SET SESSION mydb.tdf_data_attributes =
  'https://example.com/attr/clearance/value/secret';

CREATE TABLE mydb.public.employees (
  id          INT,
  _tdf_name   VARBINARY,
  _tdf_salary VARBINARY
);

INSERT INTO mydb.public.employees (id, name, salary)
VALUES (1, 'John Doe', '100000');
```

**What is stored in the database:**

| id | \_tdf\_name | \_tdf\_salary | tdf\_policy |
|----|-------------|---------------|-------------|
| 1 | `<NanoTDF bytes>` | `<NanoTDF bytes>` | `{"tdf_policies":[["https://example.com/attr/clearance/value/secret"]],"default_policy":["https://example.com/attr/clearance/value/secret"]}` |

Both `name` and `salary` are encrypted with the same attribute. `default_policy` is populated because the table has a non-TDF column (`id`).

#### Example 2: Column-level policy via INSERT

```sql
INSERT INTO mydb.public.employees (id, name, salary, tdf_policy)
VALUES (
  2,
  'Jane Doe',
  '150000',
  JSON '{"name": ["https://example.com/attr/clearance/value/secret"],
         "salary": ["https://example.com/attr/department/value/finance"],
         "default_policy": ["https://example.com/attr/clearance/value/public"]}'
);
```

**What is stored:**

| id | \_tdf\_name | \_tdf\_salary | tdf\_policy |
|----|-------------|---------------|-------------|
| 2 | `<NanoTDF bytes>` | `<NanoTDF bytes>` | `{"tdf_policies":[["…/clearance/value/secret"],["…/department/value/finance"]],"default_policy":["…/clearance/value/public"]}` |

`name` and `salary` are encrypted with different attributes. Each creates a separate group in `tdf_policies`.

#### Example 3: Pre-encrypted NanoTDF cells

Clients can send pre-encrypted NanoTDF values. Attributes are extracted from the NanoTDF header and added to the policy column automatically. NanoTDFs **must** use `EMBEDDED_POLICY_PLAIN_TEXT` policy type.

```sql
SET SESSION mydb.tdf_data_attributes =
  'https://example.com/attr/department/value/engineering';

INSERT INTO mydb.public.employees (id, name, salary)
VALUES (
  3,
  '<pre-encrypted NanoTDF bytes for name>',
  '125000'
);
```

The NanoTDF's embedded attributes become one group in `tdf_policies`. The plaintext `salary` is transparently encrypted using the session attribute. The `id` column is protected by `default_policy` given by the session attribute.

---

## Read Path: How Access Is Controlled on SELECT

When a user runs a query, TDF Trino enforces access in two stages:

1. **Row visibility trimming** — filters out entire rows the user is not authorized to see
2. **Column access modes** — for visible rows, determines whether each TDF column is decrypted, passed through encrypted, or redacted

### Stage 1: Row Visibility Trimming

TDF Trino retrieves the user's entitlements (attribute FQNs where the user has the `view` action) from the platform's authorization service, then applies a row filter. A row is visible to a user only if **both** conditions are met:

| Condition | Rule |
|-----------|------|
| Default policy | User's entitlements must be a **superset** of `default_policy`. If `default_policy` is empty (TDF-only tables), this condition is automatically satisfied. |
| TDF policies | User's entitlements must be a **superset** of **at least one** group in `tdf_policies`. If `tdf_policies` is empty (non-TDF-only tables), this condition is automatically satisfied. |

In other words: a user must satisfy the row-wide policy **and** at least one TDF column's policy to see the row at all.

#### Row Visibility by Table Type

| Table type | Has `default_policy`? | Has `tdf_policies`? | Visibility rule |
|------------|-----------------------|---------------------|----------------|
| Non-TDF only (e.g., all VARCHAR/INT columns) | Yes | Empty `[]` | User must match `default_policy` |
| TDF only (e.g., all `_tdf_` columns) | Empty `[]` | Yes | User must match at least one TDF policy group |
| Mixed (TDF + non-TDF columns) | Yes | Yes | User must match `default_policy` **AND** at least one TDF policy group |

#### Row Visibility Example

Given a table with column-level policy:
```json
{
  "tdf_policies": [
    ["https://example.com/attr/clearance/value/secret"],
    ["https://example.com/attr/department/value/engineering"]
  ],
  "default_policy": ["https://example.com/attr/clearance/value/public"]
}
```

| User | Entitlements (view action) | Sees row? | Why |
|------|---------------------------|-----------|-----|
| Alice | `clearance/public`, `clearance/secret` | Yes | Matches `default_policy` + first TDF group |
| Bob | `clearance/public`, `department/engineering` | Yes | Matches `default_policy` + second TDF group |
| Charlie | `clearance/public` | No | Matches `default_policy` but no TDF group |
| Dana | `clearance/secret` | No | Matches first TDF group but not `default_policy` |

### Stage 2: Column Access Modes

For each TDF column in a visible row, TDF Trino makes two authorization checks against the platform:

1. Does the user have the **view** action (default: `read`) for this cell's attributes?
2. Does the user have the **decrypt** action (default: `decrypt`) for this cell's attributes?

The combination determines what the user receives:

| View action | Decrypt action | User receives | Description |
|-------------|---------------|---------------|-------------|
| Permit | Permit | **Plaintext** | Cell is decrypted and returned as readable data |
| Permit | Deny | **Encrypted NanoTDF** | Raw ciphertext bytes are passed through |
| Deny | _(any)_ | **`REDACTED`** | The literal string `REDACTED` replaces the cell value |

Non-TDF columns are always returned as-is for visible rows.

Note: TDF Trino will attempt to decrypt any NanoTDF it detects in the output row, even if it is not in a TDF column. Users must configure and use TDF columns appropriately.

### Read Examples

Consider a table with three TDF columns, each encrypted with different attributes:

```sql
CREATE TABLE mydb.public.employees (
  id              INT,         -- default policy: clearance/public
  _tdf_name       VARBINARY,   -- attr: department/engineering
  _tdf_salary     VARBINARY,   -- attr: clearance/topsecret
  _tdf_location   VARBINARY    -- attr: clearance/secret
);
```

**Stored data (row 1):**

| id | \_tdf\_name | \_tdf\_salary | \_tdf\_location | tdf_policy |
|----|-------------|---------------|-----------------|------------|
| 1 | `<NanoTDF>` | `<NanoTDF>` | `<NanoTDF>` | `{"tdf_policies":[["…/clearance/value/topsecret"], ["…/clearance/value/secret"],["…/department/value/engineering"]],"default_policy":["…/clearance/value/public"]}` |

#### Alice: read + decrypt on `department/engineering`, read only on `clearance/secret`

```sql
SELECT * FROM mydb.public.employees;
```

| id | name | salary | location | tdf_policy |
|----|------|--------|----------|------------|
| 1 | John Doe | REDACTED | `<NanoTDF bytes>` | `{"tdf_policies":[["…/clearance/value/topsecret"], ["…/clearance/value/secret"],["…/department/value/engineering"]],"default_policy":["…/clearance/value/public"]}` |

- **name**: Alice has read + decrypt for `department/engineering` → **decrypted**
- **salary**: Alice has no actions for `clearance/topsecret` → **REDACTED**
- **location**: Alice has read (but not decrypt) for `clearance/secret` → **encrypted passthrough**

#### Bob: read + decrypt on all relevant attributes

```sql
SELECT * FROM mydb.public.employees;
```

| id | name | salary | location | tdf_policy |
|----|------|--------|----------|------------|
| 1 | John Doe | 100000 | Alaska | `{"tdf_policies":[["…/clearance/value/topsecret"], ["…/clearance/value/secret"],["…/department/value/engineering"]],"default_policy":["…/clearance/value/public"]}` |

All TDF columns are decrypted to plaintext.

#### Charlie: read only on all relevant attributes

```sql
SELECT * FROM mydb.public.employees;
```

| id | name | salary | location | tdf_policy |
|----|------|--------|----------|------------|
| 1 | `<NanoTDF bytes>` | `<NanoTDF bytes>` | `<NanoTDF bytes>` | `{"tdf_policies":[["…/clearance/value/topsecret"], ["…/clearance/value/secret"],["…/department/value/engineering"]],"default_policy":["…/clearance/value/public"]}` |

All TDF columns are returned as raw encrypted NanoTDF bytes.

---

## Data Modification

TDF Trino enforces authorization on all data modifications. Direct `UPDATE` and `DELETE` SQL statements are blocked — all row-level modifications must use `MERGE`.

```sql
-- Not allowed:
UPDATE mydb.public.employees SET salary = 150000 WHERE id = 1;  -- error
DELETE FROM mydb.public.employees WHERE id = 1;                  -- error

-- Required:
MERGE INTO mydb.public.employees t
USING (VALUES (1, 150000)) AS s(id, salary)
ON t.id = s.id
WHEN MATCHED THEN UPDATE SET salary = s.salary;
```

`TRUNCATE TABLE` and `CREATE TABLE AS SELECT` are also blocked.

### MERGE INSERT

A MERGE `WHEN NOT MATCHED THEN INSERT` clause is handled identically to a standalone `INSERT` — policy is resolved per the same priority chain, TDF columns are encrypted, and the policy column is computed and signed. No additional authorization is required.

### MERGE DELETE

A row is deleted only if the user holds both the `view` **and** `delete` actions on **every** attribute in the row's policy — across all groups in `tdf_policies` and all attributes in `default_policy`.

This is stricter than SELECT visibility, which only requires matching one group in `tdf_policies`. A user who can see a row is not necessarily authorized to delete it.

If authorization fails for a row, **the row is silently skipped** (not an error). A single MERGE statement can delete some rows and skip others based on each row's policy.

```sql
-- Alice needs view+delete on all attributes protecting the row
MERGE INTO mydb.public.employees t
USING (VALUES (1)) AS s(id)
ON t.id = s.id
WHEN MATCHED THEN DELETE;
```

### MERGE UPDATE

Column-level authorization is applied per SET column:

| Column type | Authorization check |
|-------------|---------------------|
| TDF column (`_tdf_*`) | User must hold `view` + `update` on the **existing** NanoTDF's attributes (the value being replaced) |
| Non-TDF column | User must hold `view` + `update` on the row's `default_policy` attributes |

All SET columns must pass their respective checks for the row to be updated. If any check fails, **the row is silently skipped**.

**The policy column is always recomputed** on every MERGE UPDATE, even if `tdf_policy` was not included in the SET clause. This ensures the stored policy stays accurate as NanoTDF values change.

#### Updating policy on MERGE UPDATE

To change the attributes protecting a TDF column or non-TDF columns, include `tdf_policy` in the SET clause:

```sql
-- Re-encrypt the 'name' TDF column with new attributes; preserve existing default_policy
MERGE INTO mydb.public.employees t
USING (VALUES (1, to_utf8('John Doe'))) AS s(id, name)
ON t.id = s.id
WHEN MATCHED THEN UPDATE SET name = s.name,
  tdf_policy = JSON '{"name": ["https://example.com/attr/clearance/value/top-secret"]}';
```

If `tdf_policy` is set with a column-level format that omits `default_policy`, the existing row's `default_policy` is automatically preserved. To change `default_policy`, specify it explicitly:

```sql
tdf_policy = JSON '{"default_policy": ["https://example.com/attr/clearance/value/top-secret"]}'
```

Setting `tdf_policy` alone (without any other SET column) is not supported and will produce an error.

### Authorization summary

| Operation | Required actions | On what |
|-----------|-----------------|---------|
| INSERT | _(none)_ | — |
| SELECT (row visible) | `view` | All `default_policy` attrs + at least one `tdf_policies` group |
| MERGE DELETE | `view` + `delete` | Every attribute across all groups and `default_policy` |
| MERGE UPDATE (TDF column) | `view` + `update` | Every attribute in the existing NanoTDF being replaced |
| MERGE UPDATE (non-TDF column) | `view` + `update` | Every attribute in the row's `default_policy` |

---

## Schema DDL Constraints

TDF Trino enforces constraints on `ALTER TABLE` operations to protect the integrity of the policy column and encrypted columns.

### tdf_policy column

The `tdf_policy` column is fully protected. The following operations on it are blocked:

| Operation | Error |
|-----------|-------|
| `ALTER TABLE DROP COLUMN tdf_policy` | `Cannot drop the TDF policy column` |
| `ALTER TABLE RENAME COLUMN tdf_policy TO ...` | `Cannot rename the TDF policy column` |
| `ALTER TABLE RENAME COLUMN ... TO tdf_policy` | `Cannot rename a column to 'tdf_policy'` |
| `ALTER TABLE ALTER COLUMN tdf_policy SET DATA TYPE ...` | `Cannot change the type of the TDF policy column` |
| `ALTER TABLE ADD COLUMN tdf_policy ...` | `Cannot add a column named 'tdf_policy'` |

### _tdf_ columns

| Operation | Behavior |
|-----------|----------|
| `ALTER TABLE DROP COLUMN <tdf_col>` | Blocked — `Cannot drop TDF-encrypted column` |
| `ALTER TABLE ALTER COLUMN <tdf_col> SET DATA TYPE ...` | Blocked — `Cannot change the type of TDF-encrypted column` |
| `ALTER TABLE RENAME COLUMN <tdf_col> TO <new_name>` | Allowed. The `_tdf_` prefix is preserved in the underlying database; Trino-visible name becomes `<new_name>`. |
| `ALTER TABLE RENAME COLUMN <col> TO _tdf_<name>` | Blocked — `Cannot rename a column to a name beginning with '_tdf_'` |

### Adding columns

| Column type | Rules |
|-------------|-------|
| Non-TDF column | `ALTER TABLE ADD COLUMN` is supported. Existing rows receive `NULL` for the new column. The row's existing `default_policy` governs access to this column on read. |
| `_tdf_` column | Supported without a `DEFAULT` value. Must be `VARBINARY`. Existing rows will have `NULL` for the new column; populate them via `MERGE ... WHEN MATCHED THEN UPDATE SET <col> = ...`. |
| `_tdf_` column with `DEFAULT` | Blocked — TDF cannot encrypt a default value at DDL time or assign it a policy. Omit the default and populate the column via `MERGE`. |
| Column named `tdf_policy` | Blocked — reserved name. |

---

## Table Lifecycle Summary

The following walks through a table's full lifecycle from creation to query.

### 1. Create Table

```sql
CREATE TABLE mydb.public.employees (
  id          INT,
  _tdf_name   VARBINARY,
  _tdf_salary VARBINARY
);
```

TDF Trino automatically adds the `tdf_policy` column. Users see:

```
SHOW COLUMNS FROM mydb.public.employees;

 Column     |   Type    | Comment
------------+-----------+------------
 id         | integer   |
 name       | varbinary | TDF column
 salary     | varbinary | TDF column
 tdf_policy | json      |
```

Note: Column names are shown without the `_tdf_` prefix, but TDF columns are discoverable via the comment.

### 2. Insert Data

```sql
SET SESSION mydb.tdf_data_attributes =
  'https://example.com/attr/clearance/value/secret,https://example.com/attr/department/value/engineering';

INSERT INTO mydb.public.employees (id, name, salary)
VALUES (1, 'John Doe', '100000');
```

Plaintext values are transparently encrypted into NanoTDFs. The policy column is populated with the resolved attributes.

### 3. Query Data

```sql
-- Alice has read+decrypt for both attributes
SELECT * FROM mydb.public.employees;

 id | name     | salary | tdf_policy |
----+----------+--------+------------
  1 | John Doe | 100000 | {"tdf_policies":[["…/clearance/value/secret", "…/department/value/engineering"]],"default_policy":["…/clearance/value/secret", "…/department/value/engineering"]} |
```

```sql
-- Bob has read (no decrypt) for both attributes
SELECT * FROM mydb.public.employees;

 id | name        | salary      | tdf_policy |
----+-------------+-------------+------------
  1 | <NanoTDF>   | <NanoTDF>   | {"tdf_policies":[["…/clearance/value/secret", "…/department/value/engineering"]],"default_policy":["…/clearance/value/secret", "…/department/value/engineering"]} |
```

```sql
-- Charlie has no matching attributes
SELECT * FROM mydb.public.employees;

 (0 rows)
```

---

## Validation and Errors

TDF Trino validates inputs at multiple stages:

| Stage | Validation | Error |
|-------|-----------|-------|
| CREATE TABLE | `_tdf_` columns must be type `VARBINARY` | `_tdf_ columns must be of type varbinary` |
| CREATE TABLE | `tdf_policy` is a reserved column name | `reserved for row policy` |
| CREATE TABLE | `default_policy` is a reserved column name | `reserved for policy specification` |
| CREATE TABLE | Table must declare a `tdf_primary_key` property | `TDF-managed tables require a tdf_primary_key table property` |
| ALTER TABLE ADD COLUMN | `tdf_policy` is a reserved column name | `Cannot add a column named 'tdf_policy'` |
| ALTER TABLE ADD COLUMN | `_tdf_` columns must be type `VARBINARY` | `_tdf_ columns must be of type varbinary` |
| ALTER TABLE ADD COLUMN | `_tdf_` columns may not carry a default value | `Cannot add TDF-encrypted column '...' with a default value` |
| ALTER TABLE DROP COLUMN | `tdf_policy` column cannot be dropped | `Cannot drop the TDF policy column` |
| ALTER TABLE DROP COLUMN | `_tdf_` columns cannot be dropped | `Cannot drop TDF-encrypted column '...'` |
| ALTER TABLE RENAME COLUMN | `tdf_policy` column cannot be renamed | `Cannot rename the TDF policy column` |
| ALTER TABLE RENAME COLUMN | Non-TDF columns cannot be renamed to `tdf_policy` | `Cannot rename a column to 'tdf_policy'` |
| ALTER TABLE RENAME COLUMN | Non-TDF columns cannot be renamed to a `_tdf_` prefix | `Cannot rename a column to a name beginning with '_tdf_'` |
| ALTER TABLE SET DATA TYPE | `tdf_policy` column type cannot be changed | `Cannot change the type of the TDF policy column` |
| ALTER TABLE SET DATA TYPE | `_tdf_` column types cannot be changed | `Cannot change the type of TDF-encrypted column '...'` |
| INSERT | NanoTDF must use `EMBEDDED_POLICY_PLAIN_TEXT` policy type | `Could not parse NanoTDF header, policy type must be EMBEDDED_POLICY_PLAIN_TEXT` |
| INSERT | Attribute FQNs must be well-formed (`https://` scheme) | `Invalid attribute FQN` |
| INSERT | Column-level policy keys must match actual TDF column names | `not a valid policy key` |
| INSERT | Transparent encryption requires resolvable policy | `Transparent encryption required at position N but no policy could be resolved` |
| INSERT | Mixed tables require `default_policy` | `default_policy required at position N` |
| SELECT / MERGE | `policy_tag` in stored `tdf_policy` does not match computed HMAC | `policy_tag verification failed` |
| UPDATE (SQL) | Direct `UPDATE` is blocked; use MERGE | `Direct UPDATE is not supported on TDF-managed tables. Use MERGE instead.` |
| DELETE (SQL) | Direct `DELETE` is blocked; use MERGE | `Direct DELETE is not supported on TDF-managed tables. Use MERGE instead.` |
| TRUNCATE TABLE | Not supported | `TRUNCATE TABLE is not supported on TDF-managed tables` |
| CREATE TABLE AS SELECT | Not supported | `CREATE TABLE AS SELECT is not supported on TDF-managed tables` |
| MERGE UPDATE | Setting `tdf_policy` alone (without any other column) is not allowed | `MERGE UPDATE SET tdf_policy alone is not supported` |

---

## Configuration Reference

Properties that control data protection behavior. For the full connector configuration (connection URLs, credentials, etc.), see [index.md](./index.md).

| Property | Default | Description |
|----------|---------|-------------|
| `tdf.policy-column` | `tdf_policy` | Name of the auto-managed policy column |
| `tdf.policy-signing-secret` | _(required)_ | Secret key used to sign and verify `policy_tag` HMAC-SHA256 on every write and read. Must be the same value across all nodes in a cluster. Treat as a credential. |
| `tdf.action.view` | `read` | Action name checked for row visibility |
| `tdf.action.decrypt` | `decrypt` | Action name checked for TDF column decryption |
| `tdf.action.update` | `update` | Action name checked (with `view`) for MERGE UPDATE authorization |
| `tdf.action.delete` | `delete` | Action name checked (with `view`) for MERGE DELETE authorization |
| `tdf.default-data-attributes` | _(none)_ | Comma-separated attribute FQNs used as the lowest-priority policy fallback on INSERT |

| Session Property | Default | Description |
|-----------------|---------|-------------|
| `<catalog>.tdf_data_attributes` | _(empty)_ | Attribute FQNs for INSERT-time policy. Supports comma-separated string, JSON array, or JSON object for column-level control. |
