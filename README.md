## What have been done
- Created the new folder structure
- Resolved state of compilation errors for files under `src`:
    1. `bigquery_constants.bal`: Fixed to compile 
    2. `bigquery_data_mappings.bal`: Fixed to compile
    3. `bigquery_endpoint.bal`
        - `invalid operation: type 'json' does not support field access for assignment`
        - `undefined annotation 'sensitive'`
        - `invalid operation: type 'record {| string message?; $error0 cause?; (anydata|error)...; |}' does not support fiel
d access for non-required field 'message'`
    4. `bigquery_types.bal`: Fixed to compile
    5. `bigquery_utils.bal`
        - `invalid operation: type '(json|error)' does not support indexing`
    6. `jwt_issuer.bal`
        - `invalid operation: type 'json' does not support indexing`
    7. `jwt_utils.bal`
        - `invalid operation: type 'json' does not support indexing`

##Pending Tasks
- Test cases have not been tried yet. First the compilation errors have to be solved.
- Credentials for BigQuery has to be obtained.
- Copy each and every artifact from the old file structure (including `README` and stuff).