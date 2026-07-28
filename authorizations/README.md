# Protected workflow reauthorization records

A reauthorization record is public evidence for one exceptional execution of
public-publish or package-channels. The workflow may execute from only the
matching ref:

refs/tags/release-reauthorization/<tag>/<stage>/<replacement-commit>

The record lives at
authorizations/<tag>/<stage>/<replacement-commit>.json and is validated
against schemas/workflow-reauthorization.schema.json. It binds the original
workflow path, commit, and digest to the replacement workflow, records the
reason, and includes non-empty approval evidence. A normal release execution
uses refs/tags/<tag> and does not need a record.
