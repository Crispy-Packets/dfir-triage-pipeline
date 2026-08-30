"""Week 3: entity resolution, rule loading, correlation.

Person A owns this package. It reads `Event` objects and never constructs or
mutates one -- `Event` is frozen by CD-005 and belongs to Person B.

`CD-021` names `core/entity.py` as the owner of executable extraction from a
service ImagePath. That clause is what put this package inside
`dfir_triage_pipeline/` rather than beside `rules/`.
"""
