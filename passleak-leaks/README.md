# Passleak Connector for OpenCTI

The **Passleak Connector** integrates Passleak lekas database with OpenCTI. This connector imports found in leaks accounts records.

## Key Features

This connector perform leaks monitoring requests. It receives records for all added to your account domains. 

## Requirements
- OpenCTI Platform version 5.10.x or higher.
- An API Key for accessing Passleak.

## Recommended connectors


## Configuration

Configuration of the connector is straightforward. The minimal configuration requires you just enter the Passleak API key to be provided and OpenCTI connection settings specified. Below is the full list of parameters you can set:

| Parameter                                                           | Docker envvar                   | Mandatory | Description                                                                                                                                                                                    |
|---------------------------------------------------------------------|---------------------------------|-----------|------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------|
| OpenCTI URL                                                         | `OPENCTI_URL`                   | Yes       | The URL of the OpenCTI platform.                                                                                                                                                               |
| OpenCTI Token                                                       | `OPENCTI_TOKEN`                 | Yes       | The default admin token set in the OpenCTI platform.                                                                                                                                           |
| Connector ID                                                        | `CONNECTOR_ID`                  | Yes       | A unique `UUIDv4` identifier for this connector instance.                                                                                                                                      |
| Connector Name                                                      | `CONNECTOR_NAME`                | Yes       | Name of the connector. For example: `Passleak`.                                                                                                                                                |
| Connector Scope                                                     | `CONNECTOR_SCOPE`               | Yes       | The scope or type of data the connector is importing, either a MIME type or Stix Object. E.g. application/json                                                                                 |
| Log Level                                                           | `CONNECTOR_LOG_LEVEL`           | Yes       | Determines the verbosity of the logs. Options are `debug`, `info`, `warn`, or `error`.                                                                                                         |
| Run and Terminate                                                   | `CONNECTOR_RUN_AND_TERMINATE`   | Yes       | If set to true, the connector will terminate after a successful run. Useful for debugging or one-time runs.                                                                                    |
| Update Existing Data                                                | `CONFIG_UPDATE_EXISTING_DATA`   | Yes       | Decide whether the connector should update already existing data in the database.                                                                                                              |
| Interval                                                            | `CONFIG_INTERVAL`               | Yes       | Determines how often the connector will run, set in hours.                                                                                                                                     |
| Passleak API Key                                                    | `PASSLEAK_API_KEY`              | Yes       | Your API Key for accessing Passleak API.                                                                                                                                                       |
| Passleak Base URL                                                   | `PASSLEAK_BASEURL`              | No        | By default, use https://api.passleka.com. In some cases, you may want to use a local API endpoint                                                                                              |
| Passleak Connection Timeout                                         | `PASSLEAK_CONTIMEOUT`           | No        | Connection timeout to the API. Default (sec): `30`                                                                                                                                             |
| Passleak Read Timeout                                               | `PASSLEAK_READTIMEOUT`          | No        | Read timeout for each feed. Our API redirects the connector to download data from AWS S3. If the connector is unable to fetch the feed in time, increase the read timeout. Default (sec): `60` |
| Passleak Fetch Interval                                             | `PASSLEAK_INTERVAL`             | No        | Default (sec): `86400`                                                                                                                                                                         |
