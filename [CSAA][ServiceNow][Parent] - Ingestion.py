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
    
    # call 'Check_SNOW_Aritifact' block
    Check_SNOW_Aritifact(container=container)

    return

def Check_SNOW_Aritifact(action=None, success=None, container=None, results=None, handle=None, filtered_artifacts=None, filtered_results=None, custom_function=None, **kwargs):
    phantom.debug('Check_SNOW_Aritifact() called')

    # collect filtered artifact ids for 'if' condition 1
    matched_artifacts_1, matched_results_1 = phantom.condition(
        container=container,
        conditions=[
            ["artifact:*.name", "==", "ServiceNow Artifact"],
        ],
        name="Check_SNOW_Aritifact:condition_1")

    # call connected blocks if filtered artifacts or results
    if matched_artifacts_1 or matched_results_1:
        Check_Ticket_Number(action=action, success=success, container=container, results=results, handle=handle, custom_function=custom_function, filtered_artifacts=matched_artifacts_1, filtered_results=matched_results_1)

    return

def configure_ticket_update(action=None, success=None, container=None, results=None, handle=None, filtered_artifacts=None, filtered_results=None, custom_function=None, **kwargs):
    phantom.debug('configure_ticket_update() called')
    
    url_value = container.get('url', None)
    id_value = container.get('id', None)
    input_parameter_0 = "ticket_resolved_state:6"
    input_parameter_1 = "cmdb_SMIR_ci:081d1e9a0f679600bf9d355be1050ee6"
    input_parameter_2 = "assigned_to:a6861194db4968504d6de5bcd3961933"
    input_parameter_3 = "close_code:Solved T3 Group"
    filtered_artifacts_data_1 = phantom.collect2(container=container, datapath=['filtered-data:Check_SNOW_Aritifact:condition_1:artifact:*.cef.short_description'])
    filtered_artifacts_item_1_0 = [item[0] for item in filtered_artifacts_data_1]

    configure_ticket_update__updated_short_description = None
    configure_ticket_update__cmdb_ci = None
    configure_ticket_update__state = None
    configure_ticket_update__assigned_to = None
    configure_ticket_update__close_code = None
    configure_ticket_update__close_notes = None

    ################################################################################
    ## Custom Code Start
    ################################################################################

    configure_ticket_update__state = input_parameter_0.split(":")[1]
    configure_ticket_update__cmdb_ci = input_parameter_1.split(":")[1]
    configure_ticket_update__assigned_to = input_parameter_2.split(":")[1]
    configure_ticket_update__updated_short_description = "Handled by Phantom Container " + str(id_value) + ": " + filtered_artifacts_item_1_0[0].replace("\\", "\\\\").replace("\"", "\\\"")
    
    if len(configure_ticket_update__updated_short_description) > 160:
        configure_ticket_update__updated_short_description = configure_ticket_update__updated_short_description[:159] + "..."
    
    configure_ticket_update__close_code = input_parameter_3.split(":")[1]
    configure_ticket_update__close_notes = "Incident is being handled by the Cyber Defense Services Team in Splunk Phantom: " + url_value

    ################################################################################
    ## Custom Code End
    ################################################################################

    phantom.save_run_data(key='configure_ticket_update:updated_short_description', value=json.dumps(configure_ticket_update__updated_short_description))
    phantom.save_run_data(key='configure_ticket_update:cmdb_ci', value=json.dumps(configure_ticket_update__cmdb_ci))
    phantom.save_run_data(key='configure_ticket_update:state', value=json.dumps(configure_ticket_update__state))
    phantom.save_run_data(key='configure_ticket_update:assigned_to', value=json.dumps(configure_ticket_update__assigned_to))
    phantom.save_run_data(key='configure_ticket_update:close_code', value=json.dumps(configure_ticket_update__close_code))
    phantom.save_run_data(key='configure_ticket_update:close_notes', value=json.dumps(configure_ticket_update__close_notes))
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
\"close_notes\": \"{5}\"
}}"""

    # parameter list for template variable replacement
    parameters = [
        "configure_ticket_update:custom_function:state",
        "configure_ticket_update:custom_function:cmdb_ci",
        "configure_ticket_update:custom_function:assigned_to",
        "configure_ticket_update:custom_function:updated_short_description",
        "configure_ticket_update:custom_function:close_code",
        "configure_ticket_update:custom_function:close_notes",
    ]

    phantom.format(container=container, template=template, parameters=parameters, name="format_ticket_json_with_CI", separator=", ")

    update_ticket_with_CI(container=container)

    return

def promote_to_case(action=None, success=None, container=None, results=None, handle=None, filtered_artifacts=None, filtered_results=None, custom_function=None, **kwargs):
    phantom.debug('promote_to_case() called')

    phantom.set_status(container=container, status="Open")

    phantom.promote(container=container, template="NIST 800-61")
    get_current_timestamp(container=container)
    Check_for_priority(container=container)

    return

def update_ticket_with_CI(action=None, success=None, container=None, results=None, handle=None, filtered_artifacts=None, filtered_results=None, custom_function=None, **kwargs):
    phantom.debug('update_ticket_with_CI() called')

    # collect data for 'update_ticket_with_CI' call
    filtered_artifacts_data_1 = phantom.collect2(container=container, datapath=['filtered-data:Check_Ticket_Number:condition_1:artifact:*.cef.number', 'filtered-data:Check_Ticket_Number:condition_1:artifact:*.id'])
    formatted_data_1 = phantom.get_format_data(name='format_ticket_json_with_CI')

    parameters = []
    
    # build parameters list for 'update_ticket_with_CI' call
    for filtered_artifacts_item_1 in filtered_artifacts_data_1:
        if filtered_artifacts_item_1[0]:
            parameters.append({
                'id': filtered_artifacts_item_1[0],
                'table': "incident",
                'fields': formatted_data_1,
                'vault_id': "",
                'is_sys_id': "",
                # context (artifact id) is added to associate results with the artifact
                'context': {'artifact_id': filtered_artifacts_item_1[1]},
            })

    phantom.act(action="update ticket", parameters=parameters, assets=['snow_dev'], callback=Check_Update_with_CI_Status, name="update_ticket_with_CI")

    return

def decision_1(action=None, success=None, container=None, results=None, handle=None, filtered_artifacts=None, filtered_results=None, custom_function=None, **kwargs):
    phantom.debug('decision_1() called')

    # check for 'if' condition 1
    matched = phantom.decision(
        container=container,
        conditions=[
            ["filtered-data:Check_Ticket_Number:condition_1:artifact:*.cef.cmdb_ci", "==", None],
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
\"close_notes\": \"{4}\"
}}"""

    # parameter list for template variable replacement
    parameters = [
        "configure_ticket_update:custom_function:state",
        "configure_ticket_update:custom_function:assigned_to",
        "configure_ticket_update:custom_function:updated_short_description",
        "configure_ticket_update:custom_function:close_code",
        "configure_ticket_update:custom_function:close_notes",
    ]

    phantom.format(container=container, template=template, parameters=parameters, name="format_ticket_json_without_CI", separator=", ")

    update_ticket_without_CI(container=container)

    return

def update_ticket_without_CI(action=None, success=None, container=None, results=None, handle=None, filtered_artifacts=None, filtered_results=None, custom_function=None, **kwargs):
    phantom.debug('update_ticket_without_CI() called')

    # collect data for 'update_ticket_without_CI' call
    filtered_artifacts_data_1 = phantom.collect2(container=container, datapath=['filtered-data:Check_Ticket_Number:condition_1:artifact:*.cef.number', 'filtered-data:Check_Ticket_Number:condition_1:artifact:*.id'])
    formatted_data_1 = phantom.get_format_data(name='format_ticket_json_without_CI')

    parameters = []
    
    # build parameters list for 'update_ticket_without_CI' call
    for filtered_artifacts_item_1 in filtered_artifacts_data_1:
        if filtered_artifacts_item_1[0]:
            parameters.append({
                'id': filtered_artifacts_item_1[0],
                'table': "incident",
                'fields': formatted_data_1,
                'vault_id': "",
                'is_sys_id': "",
                # context (artifact id) is added to associate results with the artifact
                'context': {'artifact_id': filtered_artifacts_item_1[1]},
            })

    phantom.act(action="update ticket", parameters=parameters, assets=['snow_dev'], callback=Check_Update_without_CI_Status, name="update_ticket_without_CI")

    return

def Check_Ticket_Number(action=None, success=None, container=None, results=None, handle=None, filtered_artifacts=None, filtered_results=None, custom_function=None, **kwargs):
    phantom.debug('Check_Ticket_Number() called')

    # collect filtered artifact ids for 'if' condition 1
    matched_artifacts_1, matched_results_1 = phantom.condition(
        container=container,
        conditions=[
            ["filtered-data:Check_SNOW_Aritifact:condition_1:artifact:*.cef.number", "!=", None],
        ],
        name="Check_Ticket_Number:condition_1")

    # call connected blocks if filtered artifacts or results
    if matched_artifacts_1 or matched_results_1:
        promote_to_case(action=action, success=success, container=container, results=results, handle=handle, custom_function=custom_function, filtered_artifacts=matched_artifacts_1, filtered_results=matched_results_1)

    return

def Check_Update_with_CI_Status(action=None, success=None, container=None, results=None, handle=None, filtered_artifacts=None, filtered_results=None, custom_function=None, **kwargs):
    phantom.debug('Check_Update_with_CI_Status() called')

    # check for 'if' condition 1
    matched = phantom.decision(
        container=container,
        action_results=results,
        conditions=[
            ["update_ticket_with_CI:action_result.status", "==", "success"],
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
            ["update_ticket_without_CI:action_result.status", "==", "success"],
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
    
    template = """ServiceNow {0} has been resolved and updated with container information."""

    # parameter list for template variable replacement
    parameters = [
        "filtered-data:Check_Ticket_Number:condition_1:artifact:*.cef.number",
    ]

    phantom.format(container=container, template=template, parameters=parameters, name="format_success_with_CI", separator=", ")

    document_success_status_with_CI(container=container)

    return

def join_format_success_with_CI(action=None, success=None, container=None, results=None, handle=None, filtered_artifacts=None, filtered_results=None, custom_function=None):
    phantom.debug('join_format_success_with_CI() called')
    
    # if the joined function has already been called, do nothing
    if phantom.get_run_data(key='join_format_success_with_CI_called'):
        return

    # no callbacks to check, call connected block "format_success_with_CI"
    phantom.save_run_data(key='join_format_success_with_CI_called', value='format_success_with_CI', auto=True)

    format_success_with_CI(container=container, handle=handle)
    
    return

def format_failure_with_CI(action=None, success=None, container=None, results=None, handle=None, filtered_artifacts=None, filtered_results=None, custom_function=None, **kwargs):
    phantom.debug('format_failure_with_CI() called')
    
    template = """Failed to resolve ServiceNow {0}"""

    # parameter list for template variable replacement
    parameters = [
        "filtered-data:Check_Ticket_Number:condition_1:artifact:*.cef.number",
    ]

    phantom.format(container=container, template=template, parameters=parameters, name="format_failure_with_CI", separator=", ")

    document_failure_status_with_CI(container=container)

    return

def join_format_failure_with_CI(action=None, success=None, container=None, results=None, handle=None, filtered_artifacts=None, filtered_results=None, custom_function=None):
    phantom.debug('join_format_failure_with_CI() called')
    
    # if the joined function has already been called, do nothing
    if phantom.get_run_data(key='join_format_failure_with_CI_called'):
        return

    # no callbacks to check, call connected block "format_failure_with_CI"
    phantom.save_run_data(key='join_format_failure_with_CI_called', value='format_failure_with_CI', auto=True)

    format_failure_with_CI(container=container, handle=handle)
    
    return

def document_success_status_with_CI(action=None, success=None, container=None, results=None, handle=None, filtered_artifacts=None, filtered_results=None, custom_function=None, **kwargs):
    phantom.debug('document_success_status_with_CI() called')

    formatted_data_1 = phantom.get_format_data(name='format_success_with_CI')

    phantom.pin(container=container, data="", message=formatted_data_1, pin_type="card", pin_style="grey", name="Successfully updated SNOW ticket")

    phantom.comment(container=container, comment=formatted_data_1)

    return

def document_failure_status_with_CI(action=None, success=None, container=None, results=None, handle=None, filtered_artifacts=None, filtered_results=None, custom_function=None, **kwargs):
    phantom.debug('document_failure_status_with_CI() called')

    formatted_data_1 = phantom.get_format_data(name='format_failure_with_CI')

    phantom.pin(container=container, data="", message=formatted_data_1, pin_type="card", pin_style="red", name="Failed to update SNOW ticket")

    phantom.comment(container=container, comment=formatted_data_1)

    return

def format_subject(action=None, success=None, container=None, results=None, handle=None, filtered_artifacts=None, filtered_results=None, custom_function=None, **kwargs):
    phantom.debug('format_subject() called')
    
    template = """{0} Incident {1} has been promoted to a case in Phantom"""

    # parameter list for template variable replacement
    parameters = [
        "filtered-data:Check_priority_msg:condition_1:cf_cds_playbooks_prod_get_snow_priority_str_copy_1:custom_function_result.data.priority_str",
        "filtered-data:Check_Ticket_Number:condition_1:artifact:*.cef.number",
    ]

    phantom.format(container=container, template=template, parameters=parameters, name="format_subject", separator=", ")

    format_body(container=container)

    return

def format_body(action=None, success=None, container=None, results=None, handle=None, filtered_artifacts=None, filtered_results=None, custom_function=None, **kwargs):
    phantom.debug('format_body() called')
    
    template = """%%
Click here to view the case: {0}

Phantom Container {1} - {2}

Description -

{3}
%%"""

    # parameter list for template variable replacement
    parameters = [
        "container:url",
        "container:id",
        "container:name",
        "filtered-data:Check_Ticket_Number:condition_1:artifact:*.cef.description",
    ]

    phantom.format(container=container, template=template, parameters=parameters, name="format_body", separator=", ")

    send_email_2(container=container)

    return

def send_email_2(action=None, success=None, container=None, results=None, handle=None, filtered_artifacts=None, filtered_results=None, custom_function=None, **kwargs):
    phantom.debug('send_email_2() called')
        
    #phantom.debug('Action: {0} {1}'.format(action['name'], ('SUCCEEDED' if success else 'FAILED')))
    
    # collect data for 'send_email_2' call
    formatted_data_1 = phantom.get_format_data(name='format_body')
    formatted_data_2 = phantom.get_format_data(name='format_subject')

    parameters = []
    
    # build parameters list for 'send_email_2' call
    parameters.append({
        'cc': "",
        'to': "DLITSecurityIncidentResponse@csaa.com, cybersoc@csaa.com",
        'bcc': "",
        'body': formatted_data_1,
        'from': "",
        'headers': "",
        'subject': formatted_data_2,
        'attachments': "",
    })

    phantom.act(action="send email", parameters=parameters, assets=['csaa-smtp'], name="send_email_2")

    return

def Check_priority_msg(action=None, success=None, container=None, results=None, handle=None, filtered_artifacts=None, filtered_results=None, custom_function=None, **kwargs):
    phantom.debug('Check_priority_msg() called')

    # collect filtered artifact ids for 'if' condition 1
    matched_artifacts_1, matched_results_1 = phantom.condition(
        container=container,
        action_results=results,
        conditions=[
            ["cf_cds_playbooks_prod_get_snow_priority_str_copy_1:custom_function_result.data.priority_str", "!=", None],
        ],
        name="Check_priority_msg:condition_1")

    # call connected blocks if filtered artifacts or results
    if matched_artifacts_1 or matched_results_1:
        format_subject(action=action, success=success, container=container, results=results, handle=handle, custom_function=custom_function, filtered_artifacts=matched_artifacts_1, filtered_results=matched_results_1)

    return

def cf_cds_playbooks_prod_get_snow_priority_str_copy_1(action=None, success=None, container=None, results=None, handle=None, filtered_artifacts=None, filtered_results=None, custom_function=None, **kwargs):
    phantom.debug('cf_cds_playbooks_prod_get_snow_priority_str_copy_1() called')
    
    filtered_artifacts_data_0 = phantom.collect2(container=container, datapath=['filtered-data:Check_Ticket_Number:condition_1:artifact:*.cef.priority'])

    parameters = []

    for item0 in filtered_artifacts_data_0:
        parameters.append({
            'priority_num': item0[0],
        })
    ################################################################################
    ## Custom Code Start
    ################################################################################

    # Write your custom code here...

    ################################################################################
    ## Custom Code End
    ################################################################################    

    # call custom function "cds-playbooks-prod/get_snow_priority_str_copy", returns the custom_function_run_id
    phantom.custom_function(custom_function='cds-playbooks-prod/get_snow_priority_str_copy', parameters=parameters, name='cf_cds_playbooks_prod_get_snow_priority_str_copy_1', callback=Check_priority_msg)

    return

def Check_for_priority(action=None, success=None, container=None, results=None, handle=None, filtered_artifacts=None, filtered_results=None, custom_function=None, **kwargs):
    phantom.debug('Check_for_priority() called')

    # collect filtered artifact ids for 'if' condition 1
    matched_artifacts_1, matched_results_1 = phantom.condition(
        container=container,
        conditions=[
            ["filtered-data:Check_Ticket_Number:condition_1:artifact:*.cef.priority", "!=", None],
        ],
        name="Check_for_priority:condition_1")

    # call connected blocks if filtered artifacts or results
    if matched_artifacts_1 or matched_results_1:
        cf_cds_playbooks_prod_get_snow_priority_str_copy_1(action=action, success=success, container=container, results=results, handle=handle, custom_function=custom_function, filtered_artifacts=matched_artifacts_1, filtered_results=matched_results_1)

    return

def get_current_timestamp(action=None, success=None, container=None, results=None, handle=None, filtered_artifacts=None, filtered_results=None, custom_function=None, **kwargs):
    phantom.debug('get_current_timestamp() called')
    
    input_parameter_0 = ""

    get_current_timestamp__current_timestamp = None

    ################################################################################
    ## Custom Code Start
    ################################################################################

    get_current_timestamp__current_timestamp = int(time.time())
    phantom.debug(get_current_timestamp__current_timestamp)

    ################################################################################
    ## Custom Code End
    ################################################################################

    phantom.save_run_data(key='get_current_timestamp:current_timestamp', value=json.dumps(get_current_timestamp__current_timestamp))
    filter_5(container=container)

    return

def add_time_delta(action=None, success=None, container=None, results=None, handle=None, filtered_artifacts=None, filtered_results=None, custom_function=None, **kwargs):
    phantom.debug('add_time_delta() called')
    
    get_current_timestamp__current_timestamp = json.loads(phantom.get_run_data(key='get_current_timestamp:current_timestamp'))
    filtered_artifacts_data_1 = phantom.collect2(container=container, datapath=['filtered-data:filter_5:condition_1:artifact:*.cef.priority'])
    filtered_artifacts_item_1_0 = [item[0] for item in filtered_artifacts_data_1]

    add_time_delta__delta_timestamp = None

    ################################################################################
    ## Custom Code Start
    ################################################################################

    timestamp = int(get_current_timestamp__current_timestamp)
    
    success, message, delta_values = phantom.get_list(list_name='Priority Closing Times')
    phantom.debug(delta_values)
    
    delta_dict = {x[0]: x[1] for x in delta_values}
    phantom.debug(delta_dict)
    
    phantom.debug(filtered_artifacts_item_1_0)
    
    snow_priority = filtered_artifacts_item_1_0[0]
    delta = int(delta_dict.get(snow_priority, 14400))
    phantom.debug(delta)
    
    add_time_delta__delta_timestamp = timestamp + delta
    phantom.debug(add_time_delta__delta_timestamp)

    ################################################################################
    ## Custom Code End
    ################################################################################

    phantom.save_run_data(key='add_time_delta:delta_timestamp', value=json.dumps(add_time_delta__delta_timestamp))
    add_autoclose_artifact(container=container)

    return

def filter_5(action=None, success=None, container=None, results=None, handle=None, filtered_artifacts=None, filtered_results=None, custom_function=None, **kwargs):
    phantom.debug('filter_5() called')

    # collect filtered artifact ids for 'if' condition 1
    matched_artifacts_1, matched_results_1 = phantom.condition(
        container=container,
        conditions=[
            ["artifact:*.name", "==", "ServiceNow Artifact"],
        ],
        name="filter_5:condition_1")

    # call connected blocks if filtered artifacts or results
    if matched_artifacts_1 or matched_results_1:
        add_time_delta(action=action, success=success, container=container, results=results, handle=handle, custom_function=custom_function, filtered_artifacts=matched_artifacts_1, filtered_results=matched_results_1)

    return

def add_autoclose_artifact(action=None, success=None, container=None, results=None, handle=None, filtered_artifacts=None, filtered_results=None, custom_function=None, **kwargs):
    phantom.debug('add_autoclose_artifact() called')
    
    add_time_delta__delta_timestamp = json.loads(phantom.get_run_data(key='add_time_delta:delta_timestamp'))

    ################################################################################
    ## Custom Code Start
    ################################################################################

    cef_data = {
        'autoclosetime': add_time_delta__delta_timestamp
    }
    
    phantom.add_artifact(
        cef_data=cef_data, label='automation', name='Auto Close Artifact',
        run_automation=False, severity='low'
    )

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