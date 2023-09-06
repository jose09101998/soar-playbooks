"""
"""

import phantom.rules as phantom
import json
from datetime import datetime, timedelta
##############################
# Start - Global Code Block

from datetime import datetime

# End - Global Code block
##############################

def on_start(container):
    phantom.debug('on_start() called')
    
    # call 'get_current_time' block
    get_current_time(container=container)

    return

def get_current_time(action=None, success=None, container=None, results=None, handle=None, filtered_artifacts=None, filtered_results=None, custom_function=None, **kwargs):
    phantom.debug('get_current_time() called')
    
    input_parameter_0 = ""

    get_current_time__current_time = None

    ################################################################################
    ## Custom Code Start
    ################################################################################

    get_current_time__current_time = int(datetime.now().timestamp())
    phantom.debug(get_current_time__current_time)

    ################################################################################
    ## Custom Code End
    ################################################################################

    phantom.save_run_data(key='get_current_time:current_time', value=json.dumps(get_current_time__current_time))
    get_containers_to_close(container=container)

    return

def get_containers_to_close(action=None, success=None, container=None, results=None, handle=None, filtered_artifacts=None, filtered_results=None, custom_function=None, **kwargs):
    phantom.debug('get_containers_to_close() called')
    
    get_current_time__current_time = json.loads(phantom.get_run_data(key='get_current_time:current_time'))

    get_containers_to_close__to_close = None

    ################################################################################
    ## Custom Code Start
    ################################################################################

    current_time = int(get_current_time__current_time)
    
    base_url = phantom.get_rest_base_url()
    phantom.debug(base_url)
    
    filtered_artifacts_url = f'{base_url}artifact?_filter_cef__autoclosetime__isnull=False&page_size=0'
    
    response = phantom.requests.get(filtered_artifacts_url, verify=False)
    response_json = response.json()
    phantom.debug(response_json)
    
    # List of containers to close and associated autoclose artifact number
    to_close = []
    
    for artifact in response_json['data']:
        artifact_id = artifact['id']
        container_id = artifact['container']
        autoclosetime = artifact['cef'].get('autoclosetime', None)
        if not autoclosetime:
            continue
            
        closetime = int(autoclosetime)
        
        if closetime < current_time:
            phantom.debug(f'Going to close SNOW incident for container {container_id} due to autoclose artifact {artifact_id}')
            to_close.append(
                {
                    'container_id': container_id,
                    'artifact_id': artifact_id
                }
            )
                
    phantom.debug(to_close)
    get_containers_to_close__to_close = to_close
    ############################################
    ################################################################################
    ## Custom Code End
    ################################################################################

    phantom.save_run_data(key='get_containers_to_close:to_close', value=json.dumps(get_containers_to_close__to_close))
    call_close_playbook(container=container)

    return

def call_close_playbook(action=None, success=None, container=None, results=None, handle=None, filtered_artifacts=None, filtered_results=None, custom_function=None, **kwargs):
    phantom.debug('call_close_playbook() called')
    
    get_containers_to_close__to_close = json.loads(phantom.get_run_data(key='get_containers_to_close:to_close'))

    ################################################################################
    ## Custom Code Start
    ################################################################################

    to_close = get_containers_to_close__to_close
    phantom.debug(to_close)
    
    base_url = phantom.get_rest_base_url()
    
    rest_body = {
        'container_id': None,
        'playbook_id': 'local/[CSAA][ServiceNow] - Close',
        'scope': 'all',
        'run': True
    }
    
    for item in to_close:
        container_id = item['container_id']
        phantom.debug(f'Running {rest_body["playbook_id"]} on container container_id')
        rest_body['container_id'] = container_id
        
        response = phantom.requests.post(f'{base_url}playbook_run', json=rest_body, verify=False)
        phantom.debug(response)

    ################################################################################
    ## Custom Code End
    ################################################################################

    return

def on_finish(container, summary):
    phantom.debug('on_finish() called')
    # This function is called after all actions are completed.
    # summary of all the action and/or all details of actions
    # can be collected here.

    # summary_json = phantom.get_summary()
    # if 'result' in summary_json:
        # for action_result in summary_json['result']:
            # if 'action_run_id' in action_result:
                # action_results = phantom.get_action_results(action_run_id=action_result['action_run_id'], result_data=False, flatten=False)
                # phantom.debug(action_results)

    return