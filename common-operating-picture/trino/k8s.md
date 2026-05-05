# Kubernetes Deployment

TDF Trino uses the upstream [TrinoDB Helm Chart](https://github.com/trinodb/charts/tree/trino-1.40.0/charts/trino). 

* Version: 1.40.0

Trino is a JVM based application; and therefore should be memory tuned per deployment needs; see the following Trino Chart values to configure these :
* [Coordinator JVM Values](https://github.com/trinodb/charts/blob/trino-1.40.0/charts/trino/values.yaml#L615)
* [Worker JVM Values](https://github.com/trinodb/charts/blob/trino-1.40.0/charts/trino/values.yaml#L800)


## Configuration

## Data Security Platform Configuration
The TDF enabled connectors share common Data Protection Platform configuration.  These are shared across across
connectors by using a Config Map and Secret.  The secret can be generated as part of the Helm Chart deployment
or supplied by the user.

### Example with catalogs enabled for the secure_vector and iceberg connectors with secrets generation

Includes example value overrides for the[Virtru pgsql](../charts/examples/pgsql.properties), 
[Virtru Secure vector](../charts/examples/securevector.properties),
[Virtru Iceberg](../charts/examples/iceberg.properties)  connectors 
and [example.values.yaml](../charts/examples/example.values.yaml)

Set secrets variables:
```shell
export PG_HOST=pg.replaceme
export PG_USER=pg-user-replaceme
export PG_PASSWORD=pg-password-replaceme
export REWRAP_CLIENT_SECRET=replaceme
export ENTITLEMENT_CLIENT_SECRET=replaceme
export ICEBERG_CLIENT_SECRET=replaceme
export SECURE_VECTOR_KEY=11111
```

#### Helm Install or Template

Set if performing dry run:
```shell
export DRY_RUN=--dry-run 
```

Set if performing install:
```shell
export HELM_CMD="upgrade --install $DRY_RUN"
```

Set if performing template:
```shell
export HELM_CMD="template"
```

Run Helm Command
```
helm $HELM_CMD trino-proxy \
    tdf-trino-0.2.0.tgz \
    -f charts/examples/iceberg.values.yaml \
    -f charts/examples/securevector.values.yaml \
    -f charts/examples/example.values.yaml \
    --set dataSecurityPlatform.entitlement.clientSecret=$ENTITLEMENT_CLIENT_SECRET \
    --set dataSecurityPlatform.rewrap.clientSecret=$REWRAP_CLIENT_SECRET \
    --set global.tdf.trino.postgres.user=$PG_USER \
    --set global.tdf.trino.postgres.password=$PG_PASSWORD \
    --set connector.secureVector.key=$SECURE_VECTOR_KEY \
    --set connector.iceberg.oauth2.clientSecret=$ICEBERG_CLIENT_SECRET
```

