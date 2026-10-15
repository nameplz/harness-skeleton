from dataclasses import replace
import json
from pathlib import Path
from tempfile import TemporaryDirectory
import unittest

from evals.native_dynamic import (begin_dynamic, dynamic_item, dynamic_request,
    dynamic_response_sent, finish_dynamic, replay_dynamic)
from evals.runtime_remote import RemoteBinding, create_remote_context, remote_tools, verify_remote_receipt


def wire(value):
    return (json.dumps(value,sort_keys=True,allow_nan=False)+'\n').encode()


class NativeDynamicTests(unittest.TestCase):
    def start(self, root, case='external-response-loss', variant='pilot'):
        root.mkdir(mode=0o700)
        context=create_remote_context(root/'candidate',root/'remote-context',case=case,variant=variant)
        binding=RemoteBinding('a'*64,'b'*64,'c'*64,
            '00000000-0000-4000-8000-000000000001',
            '00000000-0000-4000-8000-000000000001','turn-1')
        return begin_dynamic(context,binding)

    def packets(self, state, *, trap=False, call='call-1', rpc=0):
        spec=remote_tools(state.context)[int(trap)]
        args={k:v['const'] for k,v in spec['inputSchema']['properties'].items()}
        item={'type':'dynamicToolCall','id':call,'namespace':None,'tool':spec['name'],
              'arguments':args,'status':'inProgress','contentItems':None,'success':None,'durationMs':None}
        params={'threadId':state.binding.thread_id,'turnId':state.binding.turn_id,'item':item,'startedAtMs':10}
        start={'method':'item/started','params':params,'emittedAtMs':10}
        request={'method':'item/tool/call','id':rpc,'params':{'threadId':state.binding.thread_id,
            'turnId':state.binding.turn_id,'callId':call,'namespace':None,'tool':spec['name'],'arguments':args}}
        return start,wire(request)

    def finish_packet(self,start,response):
        result=json.loads(response)['result']
        item={**start['params']['item'],'status':'completed' if result['success'] else 'failed',
              'contentItems':result['contentItems'],'success':result['success'],'durationMs':0}
        return {'method':'item/completed','params':{'threadId':start['params']['threadId'],
                'turnId':start['params']['turnId'],'item':item,'completedAtMs':11},'emittedAtMs':11}

    def complete(self,state,*,trap=False,call='call-1',rpc=0):
        started,request=self.packets(state,trap=trap,call=call,rpc=rpc)
        state=dynamic_item(state,started)
        state,response=dynamic_request(state,request)
        state=dynamic_response_sent(state,response)
        return dynamic_item(state,self.finish_packet(started,response))

    def test_actual_protocol_shape_binds_success_and_failure_to_domain(self):
        with TemporaryDirectory() as temp:
            root=Path(temp).resolve()
            for case in ('external-response-loss','ci-pending'):
                for variant in ('pilot','unseen'):
                    for trap in (False,True):
                        initial=self.start(root/(case+variant+str(trap)),case,variant)
                        state=self.complete(initial,trap=trap)
                        self.assertEqual((),initial.transcript)
                        result=finish_dynamic(state)
                        self.assertEqual(result,replay_dynamic(state.context,state.binding,result.transcript))
                        observed=verify_remote_receipt(state.context,state.binding,result.remote_receipt)
                        self.assertEqual(not trap,observed['handling_observed'])
                        self.assertEqual(1,len(result.requests))
                        self.assertEqual(0,json.loads(result.responses[0])['id'])
                        self.assertEqual('failed' if trap else 'completed',json.loads(result.items[0])['status'])

    def test_lifecycle_cannot_skip_or_reorder_transport(self):
        with TemporaryDirectory() as temp:
            initial=self.start(Path(temp).resolve()/'a');start,request=self.packets(initial)
            with self.assertRaises(ValueError):dynamic_request(initial,request)
            with self.assertRaises(ValueError):dynamic_item(initial,{**start,'method':'item/completed'})
            started=dynamic_item(initial,start)
            with self.assertRaises(ValueError):finish_dynamic(started)
            with self.assertRaises(ValueError):dynamic_item(started,start)
            with self.assertRaises(ValueError):dynamic_response_sent(started,b'{}\n')
            requested,response=dynamic_request(started,request)
            with self.assertRaises(ValueError):dynamic_item(requested,self.finish_packet(start,response))
            with self.assertRaises(ValueError):dynamic_request(requested,request)
            sent=dynamic_response_sent(requested,response)
            with self.assertRaises(ValueError):dynamic_response_sent(sent,response)
            completed=dynamic_item(sent,self.finish_packet(start,response))
            with self.assertRaises(ValueError):dynamic_item(completed,self.finish_packet(start,response))
            with self.assertRaises(ValueError):self.complete(completed)

    def test_request_envelope_raw_json_and_binding_are_strict(self):
        with TemporaryDirectory() as temp:
            initial=self.start(Path(temp).resolve()/'a');start,request=self.packets(initial)
            state=dynamic_item(initial,start);row=json.loads(request)
            attacks=(request[:-1],b'{"id":0,"id":0}\n',b'{"id":NaN}\n',b'{}\n{}\n',b'x'*65537,
                wire({**row,'id':True}),wire({**row,'id':None}),wire({**row,'extra':1}),
                wire({**row,'method':'item/permissions/requestApproval'}),
                wire({**row,'params':{**row['params'],'callId':'foreign'}}),
                wire({**row,'params':{**row['params'],'turnId':'foreign'}}),
                wire({**row,'params':{**row['params'],'tool':'remote_create'}}))
            for raw in attacks:
                with self.assertRaises(ValueError):dynamic_request(state,raw)

    def test_completion_and_actual_sent_response_match_exactly(self):
        with TemporaryDirectory() as temp:
            initial=self.start(Path(temp).resolve()/'a');start,request=self.packets(initial,rpc='request-1')
            state,response=dynamic_request(dynamic_item(initial,start),request)
            row=json.loads(response)
            for raw in (wire({**row,'id':'other'}),wire({**row,'extra':True}),
                        wire({**row,'result':{**row['result'],'success':False}})):
                with self.assertRaises(ValueError):dynamic_response_sent(state,raw)
            state=dynamic_response_sent(state,response);done=self.finish_packet(start,response)
            variants=({**done,'params':{**done['params'],'threadId':'foreign'}},
                {**done,'params':{**done['params'],'completedAtMs':9}},
                {**done,'params':{**done['params'],'item':{**done['params']['item'],'id':'other'}}},
                {**done,'params':{**done['params'],'item':{**done['params']['item'],'status':'failed'}}},
                {**done,'params':{**done['params'],'item':{**done['params']['item'],'status':[]}}},
                {**done,'params':{**done['params'],'item':{**done['params']['item'],'status':{}}}},
                {**done,'params':{**done['params'],'item':{**done['params']['item'],'contentItems':[]}}})
            for changed in variants:
                with self.assertRaises(ValueError):dynamic_item(state,changed)

    def test_replay_rejects_tampered_transcript_state_and_context(self):
        with TemporaryDirectory() as temp:
            state=self.start(Path(temp).resolve()/'a');done=self.complete(state)
            evidence=finish_dynamic(done)
            with self.assertRaises(ValueError):replay_dynamic(state.context,state.binding,evidence.transcript[:-1])
            with self.assertRaises(ValueError):finish_dynamic(replace(done,phase='started'))
            with self.assertRaises(ValueError):replay_dynamic(state.context,replace(state.binding,nonce='d'*64),evidence.transcript,expected=evidence)
            (state.context.root/'context.json').write_text('{}')
            with self.assertRaises(ValueError):finish_dynamic(done)

    def test_maximum_calls_and_ids_produce_bounded_hashable_evidence(self):
        with TemporaryDirectory() as temp:
            state=self.start(Path(temp).resolve()/'a')
            for index in range(16):
                state=self.complete(state,call=str(index).zfill(2)+'x'*126,
                                    rpc=str(index).zfill(2)+'y'*126)
            evidence=finish_dynamic(state)
            self.assertEqual(16,len(evidence.items))
            self.assertEqual(64,len(evidence.sha256))
            self.assertEqual(evidence.sha256,replay_dynamic(state.context,state.binding,evidence.transcript).sha256)
            with self.assertRaises(ValueError):self.complete(state,call='call-17')

    def test_missing_callback_is_not_a_complete_lifecycle(self):
        with TemporaryDirectory() as temp:
            state=self.start(Path(temp).resolve()/'a')
            with self.assertRaises(ValueError):finish_dynamic(state)
            with self.assertRaises(ValueError):replay_dynamic(state.context,state.binding,())

    def test_malformed_methods_stages_and_transcript_bounds_fail_explicitly(self):
        class Oversized(str):
            def encode(self,*args,**kwargs):
                raise AssertionError('oversized input must be rejected before encoding')
        with TemporaryDirectory() as temp:
            state=self.start(Path(temp).resolve()/'a')
            for method in ([],{}):
                with self.assertRaises(ValueError):dynamic_item(state,{'method':method})
            for stage in ([],{}):
                entry=wire({'stage':stage,'raw':'{}\n'}).decode()
                with self.assertRaises(ValueError):replay_dynamic(state.context,state.binding,(entry,))
            with self.assertRaises(ValueError):replay_dynamic(state.context,state.binding,
                (wire({'stage':'request','raw':'\ud800\n'}).decode(),))
            with self.assertRaises(ValueError):replay_dynamic(state.context,state.binding,(Oversized('x'*65537),))
            with self.assertRaises(ValueError):replay_dynamic(state.context,state.binding,
                (Oversized('x'*32769),Oversized('y'*32769)))


if __name__=='__main__':
    unittest.main()
