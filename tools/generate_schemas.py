"""Generate the public, standalone JSON Schema contracts (no remote references)."""
import json
from pathlib import Path

S = {'type': 'string'}
N = {'type': ['string', 'null']}
I = {'type': 'integer'}
B = {'type': 'boolean'}
A = {'type': 'array', 'items': S}
ID = {'type':'string','pattern':'^[a-zA-Z0-9][a-zA-Z0-9_.-]{0,159}$'}
TEST_ID = {'type':'string','pattern':'^[a-zA-Z0-9][a-zA-Z0-9_.-]{0,79}$'}
H = {'type': 'string', 'pattern': '^[0-9a-f]{64}$'}
def enum(*values): return {'enum': list(values)}
def arr(items): return {'type': 'array', 'items': items}
def obj(properties, required=None, extra=False):
    return {'type': 'object', 'properties': properties, 'required': list(properties) if required is None else required, 'additionalProperties': extra}
def ref(name): return {'$ref': '#/$defs/' + name}
def null_ref(name): return {'anyOf': [ref(name), {'type': 'null'}]}
D = {}
D['Signature'] = obj({'error_type': S, 'location': S, 'key': S})
D['Comparator'] = {'oneOf': [obj({'mode': {'const': 'exact'}, 'base64': S}), obj({'mode': {'const': 'regex'}, 'pattern': S}), obj({'mode': {'const': 'json'}, 'value': {}})]}
D['Oracle'] = obj({'schema_version': {'const': '1.0'}, 'provenance': obj({'source': {'type':'string','minLength':1}, 'independent': B}), 'exit_code': {'type':'integer','minimum':0,'maximum':255}, 'stdout': ref('Comparator'), 'stderr': ref('Comparator')}, ['schema_version','provenance','exit_code','stdout'])
D['Limits'] = obj({'wall_seconds': {'type':'number','exclusiveMinimum':0,'maximum':120}, 'cpu_seconds': {'type':'integer','minimum':1,'maximum':60}, 'memory_mb': {'type':'integer','minimum':32,'maximum':2048}, 'pids': {'type':'integer','minimum':4,'maximum':128}, 'output_bytes': {'type':'integer','minimum':128,'maximum':16777216}, 'file_bytes': {'type':'integer','minimum':1024,'maximum':67108864}, 'build_wall_seconds': {'type':'number','minimum':1,'maximum':300}})
D['TestSpec'] = obj({'id': {'type':'string','pattern':'^[a-zA-Z0-9][a-zA-Z0-9_.-]{0,79}$'}, 'category': enum('valid','boundary','invalid','original','minimized'), 'input': S, 'sha256': H, 'oracle': N, 'signature': null_ref('Signature'), 'input_mode': enum('stdin','file','argv'), 'origin': S, 'regression': {'type': 'object'}}, ['id','category','input','oracle','signature'])
D['BuildSpec'] = obj({'command': {'type':'array','minItems':1,'items':S}, 'binary': S, 'compiler': S, 'flags': A})
D['TargetConfig'] = obj({'schema_version': {'const':'1.0'}, 'target': {'type':'string','pattern':'^[a-zA-Z0-9][a-zA-Z0-9_.-]{0,79}$'}, 'fixture': B, 'source': obj({'repo': S, 'base': S, 'candidate': S, 'diff': N, 'patch': N, 'dirty': obj({'version': enum('base','candidate'), 'path': S})}, ['repo','base','candidate']), 'builds': obj({'release': ref('BuildSpec'), 'sanitized': ref('BuildSpec')}), 'input': obj({'mode': enum('stdin','file','argv'), 'argv': {'type':'array','minItems':1,'items':S}, 'cwd': S}), 'environment': obj({'image': S, 'variables': {'type':'object','additionalProperties':S}}), 'tools': {'type':'object','minProperties':1,'additionalProperties':S}, 'limits': ref('Limits'), 'tests': {'type':'array','minItems':1,'items':ref('TestSpec')}, 'corpus_dir': S, 'analyzers': {'type':'array','items':enum('fixture-marker')}, 'minimization': obj({'max_attempts': {'type':'integer','minimum':1,'maximum':10000}, 'wall_seconds': {'type':'number','minimum':1,'maximum':3600}})})
D['TestCase'] = obj({'schema_version': {'const':'1.0'}, 'id': TEST_ID, 'target': ID, 'category': enum('valid','boundary','invalid','original','minimized'), 'input': S, 'sha256': H, 'size': {'type':'integer','minimum':0}, 'input_mode': enum('stdin','file','argv'), 'oracle': null_ref('Oracle'), 'signature': null_ref('Signature'), 'origin': S, 'regression': {'type':['object','null']}})
D['BuildRecord'] = obj({'schema_version': {'const':'1.0'}, 'id': ID, 'version': enum('base','candidate'), 'build_type': enum('release','sanitized'), 'commit': S, 'source': {'type':'object'}, 'binary': N, 'binary_sha256': {'anyOf':[H,{'type':'null'}]}, 'architecture': enum('x86_64','unknown'), 'file_type': enum('ELF','unknown'), 'compiler': {'type':'object'}, 'flags': A, 'command': A, 'environment': {'type':'object'}, 'result': enum('success','failed'), 'error': N, 'stdout': S, 'stderr': S, 'hardening': {'type':'object'}, 'evidence': A})
D['RunRecord'] = obj({'schema_version': {'const':'1.0'}, 'id': ID, 'version': enum('base','candidate'), 'build_type': enum('release','sanitized'), 'build_id': ID, 'test_id': TEST_ID, 'input': S, 'input_sha256': H, 'command': A, 'cwd': S, 'environment': {'type':'object'}, 'limits': ref('Limits'), 'duration_seconds': {'type':'number','minimum':0}, 'exit_code': {'type':['integer','null'],'minimum':0,'maximum':255}, 'signal': {'type':['integer','null'],'minimum':1}, 'timeout': B, 'resource_status': enum('ok','cpu_limit','memory_limit','file_limit','output_limit','unknown'), 'output_truncated': B, 'runner_error': N, 'stdout': S, 'stderr': S, 'stdout_sha256': H, 'stderr_sha256': H, 'diagnostics': A, 'trace': A, 'rusage': {'type':'object'}, 'sandbox': {'type':'object'}, 'oracle': {'type':'object'}, 'analysis': {'type':'object'}, 'replay_of': N})
D['Finding'] = obj({'schema_version': {'const':'1.0'}, 'id': ID, 'error_type': S, 'detection_method': S, 'confirmation': enum('confirmed','fixture','unknown'), 'signature': null_ref('Signature'), 'location': N, 'base_run_ids': A, 'candidate_run_ids': A, 'replay_stability': enum('stable','unstable','not_run','unknown'), 'status': enum('Fixed','Incomplete Fix','New Issue','Functional Regression','Inconclusive'), 'root_cause': N, 'evidence_sufficiency': enum('sufficient','fixture_only','insufficient'), 'evidence': A, 'complete_evidence': B})
D['PatchRelation'] = obj({'schema_version': {'const':'1.0'}, 'finding_id': ID, 'hunk_ids': A, 'locations': arr({'type':'object'}), 'paired_run_ids': A, 'relation': enum('confirmed','candidate','unknown','rejected'), 'evidence': A, 'limitation': S})
D['OracleEvaluation'] = obj({'status': enum('pass','fail','unknown'), 'reason': S, 'checks': {'type':'object','additionalProperties':B}, 'source': S}, ['status'])
D['RunRecord']['properties']['oracle'] = ref('OracleEvaluation')
D['RunRecord']['properties']['analysis'] = obj({'complete':B, 'observations':arr({'type':'object'}), 'reason':S, 'fixture_observation':{'type':['object','null']}}, ['complete','observations','reason'])
D['RunRecord']['oneOf'] = [
 {'properties':{'exit_code':{'type':'integer'},'signal':{'type':'null'}}},
 {'properties':{'exit_code':{'type':'null'},'signal':{'type':'integer'}}},
 {'properties':{'exit_code':{'type':'null'},'signal':{'type':'null'}}}]
D['FunctionalPair'] = obj({'test_id':TEST_ID,'build_type':enum('release','sanitized'),'base':enum('pass','fail','unknown'),'candidate':enum('pass','fail','unknown'),
 'status':enum('preserved','regression','both_fail','unknown','baseline_fail','invalid_behavior_changed'),
 'observed_status':enum('preserved','regression','both_fail','unknown','baseline_fail','invalid_behavior_changed'),
 'replay_stability':enum('stable','unstable','unknown','not_run'), 'base_run_id':ID,'candidate_run_id':ID,
 'generated_regression': {'type':'object','properties':{'direction':enum('base-vulnerability','candidate-only'),'base_match':enum('match','mismatch','unknown'),'candidate_absence_and_oracle':B,'candidate_match':enum('match','mismatch','unknown'),'base_absence_and_oracle':B,'status':enum('pass','unknown')},'required':['status'],'additionalProperties':False}},
 ['test_id','build_type','base','candidate','status','observed_status','replay_stability','base_run_id','candidate_run_id'])
D['Axes'] = obj({'security':obj({'status':enum('unknown','fixed','issue'),'baseline_reproduced':B,'confirmed_issues':A,'fixture_observations':{'type':'integer','minimum':0}}),
 'functional':obj({'status':enum('preserved','regression','unknown'),'comparisons':arr(ref('FunctionalPair')),'decision_engine_code':enum(0,10,20,30,40)}),
 'completeness':obj({'complete':B,'reasons':A})})
D['FinalReport'] = obj({'schema_version': {'const':'1.0'}, 'id': S, 'target': S, 'fixture': B, 'config': S, 'versions': {'type':'object'}, 'environment': {'type':'object'}, 'builds': arr(ref('BuildRecord')), 'tests': arr(ref('TestCase')), 'runs': arr(ref('RunRecord')), 'axes': ref('Axes'), 'findings': arr(ref('Finding')), 'patch_relations': arr(ref('PatchRelation')), 'diff': {'type':'object'}, 'hardening': {'type':'object'}, 'replays': arr({'type':'object'}), 'minimized': arr({'type':'object'}), 'bundles': A, 'unstable': A, 'unknowns': A, 'technical_errors': A, 'evidence_index': {'type':'object','additionalProperties':H}, 'exit_code': enum(0,10,20,30,40), 'stage': {'enum':[1,2]}})
root = Path(__file__).resolve().parents[1]
for name in ('TargetConfig','TestCase','BuildRecord','RunRecord','Finding','PatchRelation','FinalReport','Oracle'):
    needed = {name}
    pending = [name]
    while pending:
        current = pending.pop()
        import re
        for dependency in re.findall(r'#/\$defs/([A-Za-z]+)', json.dumps(D[current])):
            if dependency not in needed:
                needed.add(dependency); pending.append(dependency)
    schema = {'$schema':'https://json-schema.org/draft/2020-12/schema', '$id':'urn:patchcheck:'+name, '$ref':'#/$defs/'+name, '$defs':{key:D[key] for key in sorted(needed)}}
    data = json.dumps(schema, indent=2, ensure_ascii=False) + '\n'
    for dest in (root/'schemas',root/'src/patchcheck/schemas'):
        dest.mkdir(parents=True, exist_ok=True)
        (dest/(name+'.schema.json')).write_text(data)
