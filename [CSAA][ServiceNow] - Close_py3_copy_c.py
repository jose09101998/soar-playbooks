"""
"""

import phantom.rules as phantom
import json
from datetime import datetime, timedelta
##############################
# Start - Global Code Block

import time



# End - Global Code block
##############################

def on_start(container):
    phantom.debug('on_start() called')
    
    # call 'Get_the_current_time' block
    Get_the_current_time(container=container)

    return

def configure_ticket_update(action=None, success=None, container=None, results=None, handle=None, filtered_artifacts=None, filtered_results=None, custom_function=None, **kwargs):
    phantom.debug('configure_ticket_update() called')
    
    url_value = container.get('url', None)
    id_value = container.get('id', None)
    input_parameter_0 = "ticket_resolved_state:6"
    input_parameter_1 = "cmdb_SMIR_ci:Security Mgmt Incident Response and Cyber Defense-PROD"
    input_parameter_2 = "assigned_to:SplunkPhantom Nonprod User"
    input_parameter_3 = "close_code:Solution provided"
    input_parameter_4 = "category:Monitoring"
    container_data = phantom.collect2(container=container, datapath=['artifact:*.cef.short_description', 'artifact:*.id'])
    container_item_0 = [item[0] for item in container_data]

    configure_ticket_update__updated_short_description = None
    configure_ticket_update__cmdb_ci = None
    configure_ticket_update__state = None
    configure_ticket_update__assigned_to = None
    configure_ticket_update__close_code = None
    configure_ticket_update__close_notes = None
    configure_ticket_update__category = None

    ################################################################################
    ## Custom Code Start
    ################################################################################

    configure_ticket_update__state = input_parameter_0.split(":")[1]
    configure_ticket_update__cmdb_ci = input_parameter_1.split(":")[1]
    configure_ticket_update__assigned_to = input_parameter_2.split(":")[1]
    configure_ticket_update__updated_short_description = "Handled by Phantom Container " + str(id_value) + ": " + str(container_item_0[0]).replace("\\", "\\\\").replace("\"", "\\\"")
    phantom.debug(configure_ticket_update__updated_short_description) 
    
    '''if len(configure_ticket_update__updated_short_description) > 160:
        configure_ticket_update__updated_short_description = configure_ticket_update__updated_short_description[:159] + "..
        continue'''
    
    configure_ticket_update__close_code = input_parameter_3.split(":")[1]
    configure_ticket_update__close_notes = "Incident is being handled by the Cyber Defense Services Team in Splunk SOAR Cloud: " + url_value

    ################################################################################
    ## Custom Code End
    ################################################################################

    phantom.save_run_data(key='configure_ticket_update:updated_short_description', value=json.dumps(configure_ticket_update__updated_short_description))
    phantom.save_run_data(key='configure_ticket_update:cmdb_ci', value=json.dumps(configure_ticket_update__cmdb_ci))
    phantom.save_run_data(key='configure_ticket_update:state', value=json.dumps(configure_ticket_update__state))
    phantom.save_run_data(key='configure_ticket_update:assigned_to', value=json.dumps(configure_ticket_update__assigned_to))
    phantom.save_run_data(key='configure_ticket_update:close_code', value=json.dumps(configure_ticket_update__close_code))
    phantom.save_run_data(key='configure_ticket_update:close_notes', value=json.dumps(configure_ticket_update__close_notes))
    phantom.save_run_data(key='configure_ticket_update:category', value=json.dumps(configure_ticket_update__category))
    decision_1(container=container)

    return

def format_ticket_json_with_CI(action=None, success=None, container=None, results=None, handle=None, filtered_artifacts=None, filtered_results=None, custom_function=None, **kwargs):
    phantom.debug('format_ticket_json_with_CI() called')
    
    template = """{{
\"state\": \"{0}\",
\"cmdb_ci\": \"{1}\",
\"assigned_to\": \"{2}\",
\"short_description\": \"{3}\",
\"close_code\": \"{4}\",
\"close_notes\": \"{5}\",
\"category\":\"{6}\"
}}"""

    # parameter list for template variable replacement
    parameters = [
        "configure_ticket_update:custom_function:state",
        "configure_ticket_update:custom_function:cmdb_ci",
        "configure_ticket_update:custom_function:assigned_to",
        "configure_ticket_update:custom_function:updated_short_description",
        "configure_ticket_update:custom_function:close_code",
        "configure_ticket_update:custom_function:close_notes",
        "configure_ticket_update:custom_function:category",
    ]

    phantom.format(container=container, template=template, parameters=parameters, name="format_ticket_json_with_CI", separator=", ")

    update_ticket_6(container=container)

    return

def decision_1(action=None, success=None, container=None, results=None, handle=None, filtered_artifacts=None, filtered_results=None, custom_function=None, **kwargs):
    phantom.debug('decision_1() called')

    # check for 'if' condition 1
    matched = phantom.decision(
        container=container,
        conditions=[
            ["configure_ticket_update:custom_function:cmdb_ci", "!=", None],
        ])

    # call connected blocks if condition 1 matched
    if matched:
        format_ticket_json_with_CI(action=action, success=success, container=container, results=results, handle=handle, custom_function=custom_function)
        return

    # call connected blocks for 'else' condition 2
    format_ticket_json_without_CI(action=action, success=success, container=container, results=results, handle=handle, custom_function=custom_function)

    return

def format_ticket_json_without_CI(action=None, success=None, container=None, results=None, handle=None, filtered_artifacts=None, filtered_results=None, custom_function=None, **kwargs):
    phantom.debug('format_ticket_json_without_CI() called')
    
    template = """{{
\"state\": \"{0}\",
\"assigned_to\": \"{1}\",
\"short_description\": \"{2}\",
\"close_code\": \"{3}\",
\"close_notes\": \"{4}\",
\"category\":\"{5}\"
}}"""

    # parameter list for template variable replacement
    parameters = [
        "configure_ticket_update:custom_function:state",
        "configure_ticket_update:custom_function:assigned_to",
        "configure_ticket_update:custom_function:updated_short_description",
        "configure_ticket_update:custom_function:close_code",
        "configure_ticket_update:custom_function:close_notes",
        "configure_ticket_update:custom_function:category",
    ]

    phantom.format(container=container, template=template, parameters=parameters, name="format_ticket_json_without_CI", separator=", ")

    update_ticket_7(container=container)

    return

def Check_Update_with_CI_Status(action=None, success=None, container=None, results=None, handle=None, filtered_artifacts=None, filtered_results=None, custom_function=None, **kwargs):
    phantom.debug('Check_Update_with_CI_Status() called')

    # check for 'if' condition 1
    matched = phantom.decision(
        container=container,
        action_results=results,
        conditions=[
            ["update_ticket_6:action_result.status", "==", "success"],
        ])

    # call connected blocks if condition 1 matched
    if matched:
        join_format_success_with_CI(action=action, success=success, container=container, results=results, handle=handle, custom_function=custom_function)
        return

    # call connected blocks for 'else' condition 2
    join_format_failure_with_CI(action=action, success=success, container=container, results=results, handle=handle, custom_function=custom_function)

    return

def Check_Update_without_CI_Status(action=None, success=None, container=None, results=None, handle=None, filtered_artifacts=None, filtered_results=None, custom_function=None, **kwargs):
    phantom.debug('Check_Update_without_CI_Status() called')

    # check for 'if' condition 1
    matched = phantom.decision(
        container=container,
        action_results=results,
        conditions=[
            ["update_ticket_7:action_result.status", "==", "success"],
        ])

    # call connected blocks if condition 1 matched
    if matched:
        join_format_success_with_CI(action=action, success=success, container=container, results=results, handle=handle, custom_function=custom_function)
        return

    # call connected blocks for 'else' condition 2
    join_format_failure_with_CI(action=action, success=success, container=container, results=results, handle=handle, custom_function=custom_function)

    return

def format_success_with_CI(action=None, success=None, container=None, results=None, handle=None, filtered_artifacts=None, filtered_results=None, custom_function=None, **kwargs):
    phantom.debug('format_success_with_CI() called')
    
    template = """ServiceNow {0} has been resolved and updated with container information ."""

    # parameter list for template variable replacement
    parameters = [
        "artifact:*.cef.number",
    ]

    phantom.format(container=container, template=template, parameters=parameters, name="format_success_with_CI", separator=", ")

    document_success_status_with_CI(container=container)

    return

def join_format_success_with_CI(action=None, success=None, container=None, results=None, handle=None, filtered_artifacts=None, filtered_results=None, custom_function=None):
    phantom.debug('join_format_success_with_CI() called')
    
    # if the joined function has already been called, do nothing
    if phantom.get_run_data(key='join_format_success_with_CI_called'):
        return

    # check if all connected incoming playbooks, actions, or custom functions are done i.e. have succeeded or failed
    if phantom.completed(action_names=['update_ticket_6', 'update_ticket_7']):
        
        # save the state that the joined function has now been called
        phantom.save_run_data(key='join_format_success_with_CI_called', value='format_success_with_CI')
        
        # call connected block "format_success_with_CI"
        format_success_with_CI(container=container, handle=handle)
    
    return

def format_failure_with_CI(action=None, success=None, container=None, results=None, handle=None, filtered_artifacts=None, filtered_results=None, custom_function=None, **kwargs):
    phantom.debug('format_failure_with_CI() called')
    
    template = """Failed to resolve ServiceNow {0}"""

    # parameter list for template variable replacement
    parameters = [
        "artifact:*.cef.number",
    ]

    phantom.format(container=container, template=template, parameters=parameters, name="format_failure_with_CI", separator=", ")

    document_failure_status_with_CI(container=container)

    return

def join_format_failure_with_CI(action=None, success=None, container=None, results=None, handle=None, filtered_artifacts=None, filtered_results=None, custom_function=None):
    phantom.debug('join_format_failure_with_CI() called')
    
    # if the joined function has already been called, do nothing
    if phantom.get_run_data(key='join_format_failure_with_CI_called'):
        return

    # check if all connected incoming playbooks, actions, or custom functions are done i.e. have succeeded or failed
    if phantom.completed(action_names=['update_ticket_6', 'update_ticket_7']):
        
        # save the state that the joined function has now been called
        phantom.save_run_data(key='join_format_failure_with_CI_called', value='format_failure_with_CI')
        
        # call connected block "format_failure_with_CI"
        format_failure_with_CI(container=container, handle=handle)
    
    return

def document_success_status_with_CI(action=None, success=None, container=None, results=None, handle=None, filtered_artifacts=None, filtered_results=None, custom_function=None, **kwargs):
    phantom.debug('document_success_status_with_CI() called')

    formatted_data_1 = phantom.get_format_data(name='format_success_with_CI')

    phantom.pin(container=container, data="", message=formatted_data_1, pin_type="card", pin_style="grey", name="Successfully updated SNOW ticket")

    phantom.comment(container=container, comment=formatted_data_1)

    container = phantom.get_container(container.get('id', None))

    return

def document_failure_status_with_CI(action=None, success=None, container=None, results=None, handle=None, filtered_artifacts=None, filtered_results=None, custom_function=None, **kwargs):
    phantom.debug('document_failure_status_with_CI() called')

    formatted_data_1 = phantom.get_format_data(name='format_failure_with_CI')

    phantom.pin(container=container, data="", message=formatted_data_1, pin_type="card", pin_style="red", name="Failed to update SNOW ticket")

    phantom.comment(container=container, comment=formatted_data_1)

    container = phantom.get_container(container.get('id', None))

    return

def Autoclose_artifact(action=None, success=None, container=None, results=None, handle=None, filtered_artifacts=None, filtered_results=None, custom_function=None, **kwargs):
    phantom.debug('Autoclose_artifact() called')

    # collect filtered artifact ids for 'if' condition 1
    matched_artifacts_1, matched_results_1 = phantom.condition(
        container=container,
        conditions=[
            ["custom_function_7:custom_function:close", "!=", None],
        ],
        name="Autoclose_artifact:condition_1")

    # call connected blocks if filtered artifacts or results
    if matched_artifacts_1 or matched_results_1:
        configure_ticket_update(action=action, success=success, container=container, results=results, handle=handle, custom_function=custom_function, filtered_artifacts=matched_artifacts_1, filtered_results=matched_results_1)

    return

def Get_the_current_time(action=None, success=None, container=None, results=None, handle=None, filtered_artifacts=None, filtered_results=None, custom_function=None, **kwargs):
    phantom.debug('Get_the_current_time() called')
    
    input_parameter_0 = ""

    Get_the_current_time__current_time = None

    ################################################################################
    ## Custom Code Start
    ################################################################################

    # Write your custom code here...

    current_time = int(time.time())
    
    #buffer_time = 300
    
    Get_the_current_time__current_time = current_time

    ################################################################################
    ## Custom Code End
    ################################################################################

    phantom.save_run_data(key='Get_the_current_time:current_time', value=json.dumps(Get_the_current_time__current_time))
    custom_function_7(container=container)

    return

def custom_function_7(action=None, success=None, container=None, results=None, handle=None, filtered_artifacts=None, filtered_results=None, custom_function=None, **kwargs):
    phantom.debug('custom_function_7() called')
    
    Get_the_current_time__current_time = json.loads(phantom.get_run_data(key='Get_the_current_time:current_time'))

    custom_function_7__close = None

    ################################################################################
    ## Custom Code Start
    ################################################################################

    # Write your custom code here...
    
    current_time = Get_the_current_time__current_time
    
    close=True
    
    base_url = phantom.get_rest_base_url()
    phantom.debug(base_url)
    
    filtered_artifacts_url = f'{base_url}artifact?_filter_cef__autoclosetime__isnull=False&page_size=0'
    
    response = phantom.requests.get(filtered_artifacts_url, verify=False)
    response_json = response.json()
    phantom.debug(response_json)

    for artifact in response_json['data']:
        autoclosetime = artifact['cef'].get('autoclosetime', None)
        if not autoclosetime:
            continue
            
        closetime = int(autoclosetime)
        
        #buffer_time = 300

        if closetime == current_time :
            close
            
    custom_function_7__close = close
    phantom.debug(custom_function_7__close)
    phantom.debug(closetime)
    phantom.debug(current_time)
    #############
    #############
    #############
    #############
    #############
    #############
    #############
    #############
    #############
    #############
    #############
    #############
    #############
    #############
    #############
    #############
    #############
    #############
    #############
    #############
    #############
    #############
    #############
    #############
    #############
    ################################################################################
    ## Custom Code End
    ################################################################################

    phantom.save_run_data(key='custom_function_7:close', value=json.dumps(custom_function_7__close))
    Autoclose_artifact(container=container)

    return

def update_ticket_6(action=None, success=None, container=None, results=None, handle=None, filtered_artifacts=None, filtered_results=None, custom_function=None, **kwargs):
    phantom.debug('update_ticket_6() called')

    # collect data for 'update_ticket_6' call
    container_data = phantom.collect2(container=container, datapath=['artifact:*.cef.number', 'artifact:*.id'])
    formatted_data_1 = phantom.get_format_data(name='format_ticket_json_with_CI')

    parameters = []
    
    # build parameters list for 'update_ticket_6' call
    for container_item in container_data:
        if container_item[0]:
            parameters.append({
                'id': container_item[0],
                'table': "incident",
                'fields': formatted_data_1,
                'vault_id': "",
                'is_sys_id': "",
                # context (artifact id) is added to associate results with the artifact
                'context': {'artifact_id': container_item[1]},
            })

    phantom.act(action="update ticket", parameters=parameters, assets=['csaatest_vancouver'], callback=Check_Update_with_CI_Status, name="update_ticket_6")

    return

def update_ticket_7(action=None, success=None, container=None, results=None, handle=None, filtered_artifacts=None, filtered_results=None, custom_function=None, **kwargs):
    phantom.debug('update_ticket_7() called')

    # collect data for 'update_ticket_7' call
    container_data = phantom.collect2(container=container, datapath=['artifact:*.cef.number', 'artifact:*.id'])
    formatted_data_1 = phantom.get_format_data(name='format_ticket_json_without_CI')

    parameters = []
    
    # build parameters list for 'update_ticket_7' call
    for container_item in container_data:
        if container_item[0]:
            parameters.append({
                'id': container_item[0],
                'table': "incident",
                'fields': formatted_data_1,
                'vault_id': "",
                'is_sys_id': "",
                # context (artifact id) is added to associate results with the artifact
                'context': {'artifact_id': container_item[1]},
            })

    phantom.act(action="update ticket", parameters=parameters, assets=['snow_prod'], callback=Check_Update_without_CI_Status, name="update_ticket_7")

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