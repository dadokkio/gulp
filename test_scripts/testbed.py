#!/usr/bin/env python

from sigma.backends.opensearch import OpensearchLuceneBackend
from sigma.exceptions import SigmaError
from sigma.processing.pipeline import ProcessingPipeline
from sigma.rule import SigmaRule
from sigma.collection import SigmaCollection
from sigma.pipelines.elasticsearch.windows import ecs_windows
import json
import os
import sys

def sigma_to_gulp_rule(rule: str, references: list[str]=None, pipeline: ProcessingPipeline=None) -> list[dict]:
    r = rule

    if f is not None:
        # make a single yml string with all the references
        for ref in references:
            r += '\n---\n' + ref
        
    sc = SigmaCollection.from_yaml(r)
    sc.resolve_rule_references()
    
    if pipeline is None:
        pipeline = ProcessingPipeline()    
    
    backend = OpensearchLuceneBackend(processing_pipeline=pipeline)
    
    rules: list[dict] = []
    for rule in sc.rules:
        q = backend.convert_rule(sc.rules[0], "dsl_lucene")
        rules.append(q)

    print(json.dumps(rules, indent=2))
    return rules

if __name__ == "__main__":
    
    rule_files  = [
        '/home/valerino/Downloads/win_filter_admins.yml',
        '/home/valerino/Downloads/proc_creation_win_sc_create_service.yml',
        '/home/valerino/Downloads/proc_creation_win_custom.yml',
    ]
    rules=[]
    for rule_file in rule_files:
        with open(rule_file, 'r') as f:
            rule = f.read()
            rules.append(rule)
    rule = rules[0]
    filters = [rules[1], rules[2]]
    p: ProcessingPipeline = ecs_windows()
    r = sigma_to_gulp_rule(rule, references=filters, pipeline=p)
    #print(json.dumps(r, indent=4))
    