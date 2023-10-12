"""

"""


import phantom.rules as phantom
import json
from datetime import datetime, timedelta


@phantom.playbook_block()
def on_start(container):
    phantom.debug('on_start() called')

    # call 'add_artifact_to_close_it' block
    add_artifact_to_close_it(container=container)

    return

@phantom.playbook_block()
def add_artifact_to_close_it(action=None, success=None, container=None, results=None, handle=None, filtered_artifacts=None, filtered_results=None, custom_function=None, **kwargs):
    phantom.debug("add_artifact_to_close_it() called")

    ################################################################################
    ## Custom Code Start
    ################################################################################

    # Write your custom code here...
    
    cef_data = {
        'close': "the SNOW ticket has been closed"
    }
    
    phantom.add_artifact(
        cef_data=cef_data, label='automation', name='close',
        run_automation=False, severity='low'
    )

    ################################################################################
    ## Custom Code End
    ################################################################################

    find_the_container_ids_to_delete(container=container)

    return


@phantom.playbook_block()
def find_the_container_ids_to_delete(action=None, success=None, container=None, results=None, handle=None, filtered_artifacts=None, filtered_results=None, custom_function=None, **kwargs):
    phantom.debug("find_the_container_ids_to_delete() called")

    find_the_container_ids_to_delete__to_close = None

    ################################################################################
    ## Custom Code Start
    ################################################################################

    # Write your custom code here...
    
    base_url = phantom.get_rest_base_url()
    phantom.debug(base_url)
    
    filtered_artifacts_url = f'{base_url}artifact?_filter_cef__close__isnull=False&page_size=0'
    
    response = phantom.requests.get(filtered_artifacts_url, verify=False)
    response_json = response.json()
    phantom.debug(response_json)
    
    to_delete = []
    
    for artifact in response_json['data']:
        container_id = artifact['container']
        to_delete.append(container_id)
        endpoint = 'container/{}'.format(container_id)
        url = base_url + endpoint
        response = phantom.requests.delete(url, verify=False)
        phantom.debug("Successfully deleted the container with {0}".format(artifact))
    
    

    ################################################################################
    ## Custom Code End
    ################################################################################

    phantom.save_run_data(key="find_the_container_ids_to_delete:to_close", value=json.dumps(find_the_container_ids_to_delete__to_close))

    return


@phantom.playbook_block()
def on_finish(container, summary):
    phantom.debug("on_finish() called")

    ################################################################################
    ## Custom Code Start
    ################################################################################

    # Write your custom code here...

    ################################################################################
    ## Custom Code End
    ################################################################################

    return