from tenable.sc import TenableSC
from flask import Flask, render_template, request
import urllib.parse

app = Flask(__name__)

# Set User data
hostname = ""
username = ""
password = ""

# Set SC object
sc = TenableSC(hostname)

# login to SC


@app.route('/')
def get_info():
    sc.login(username, password)
    # Get data
    # check Development tools in chrome -> Network tab --> Under Name, choose analysis --> Headers tab --> Request Payload
    # EXAMPLE: sc.analysis.vulns(('pluginID', '=', '19506'), ('firstSeen', '=', '0:60'),('repository','=',[{"id" : "1"}]), tool='sumip')

    current_devices = []

    for device in sc.analysis.vulns(tool='sumremediation', sort_field='score', sort_direction='desc'): #(('lastSeen','=','0:30'), tool='sumip'):
        current_devices.append(device)

    # logout of SC
    sc.logout()

    return render_template('index.html', current_devices=current_devices)


@app.route('/details/<plugins>', methods=["GET"])
def get_details(plugins):
    sc.login(username, password)
    detail_info = []
    for details in sc.analysis.vulns(('pluginID', '=', plugins), tool='sumid', sort_field='vprScore', sort_direction='desc'):
        detail_info.append(details)

    sc.logout()
    return render_template('details.html', detail_info=detail_info)


@app.route('/hosts_affected/<plugin>', methods=["GET"])
def get_host_affected(plugin):
    sc.login(username, password)
    hosts_affected = []
    for hosts in sc.analysis.vulns(('pluginID', '=', plugin), tool='listvuln'):
        hosts_affected.append(hosts)

    sc.logout()
    return render_template('hosts_affected.html', hosts_affected=hosts_affected)


@app.route('/host_plugin_details/<plugin>/<ip>', methods=["GET"])
def get_host_plugin_info(plugin, ip):
    sc.login(username, password)
    host_details = []

    for deets in sc.analysis.vulns(('pluginID', '=', plugin), ('ip', '=', ip), tool='vulndetails'):
        host_details.append(deets)

    sc.logout()
    return render_template('host_plugin_details.html', host_details=host_details)


if __name__ == '__main__':
    app.run(host="0.0.0.0", port=5001)
