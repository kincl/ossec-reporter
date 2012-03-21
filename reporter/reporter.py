#ossec-reporter: reporter.py

# What we have here is a program called ossec-logtest which takes syslog entries
# and matches them agaist a rule set to find problems in systems. ossec-logtest
# will generate a event block when a rule is fired separated by a blank line.
# This program takes those events and generates basic web pages with information.

# turn off DNS lookups to speed up script
DNSDEBUG = False

import os
import re
import sys
import socket
from datetime import date, datetime
from Cheetah.Template import Template
from optparse import OptionParser

parser = OptionParser()
parser.add_option("-f", "--file", dest="report",
                  help="path to syslog report from ossec-reportd", metavar="FILE")
parser.add_option("-d", "--directory", dest="directory",
                  help="write report to DIRECTORY", metavar="DIRECTORY")
parser.add_option("-D", "--date", dest="date",
                  help="TODO Date (YYYY-MM-DD of report", metavar="YYYY-MM-DD")

(options, args) = parser.parse_args()
opts = vars(options)

if opts['report'] == None:
    parser.parse_args(['-h'])
else:
    report = open(opts['report'])
if opts['directory'] == None:
    parser.parse_args(['-h'])

try:
    os.mkdir(opts['directory'])
except OSError:
    print "Directory exists! Exiting!"
    sys.exit(1)

# These are the regex's that break down each line in a event block
line_regex =    [
                    re.compile('\*\* Alert [\d\.]+:[\w ]+- ([\w,]+)'),
                    re.compile('\d{4} \w+ \d{2} \d{2}:\d{2}:\d{2} ([\w\.\-@]+)->stdin'),
                    re.compile('Rule: (\d+) \(level (\d+)\) -> \'([\w \(\)\:\-/\.]+)\''),
                    re.compile('Src IP: ([\w\.:\(\)\-]+)'),
                    re.compile('User: ([\w\(\)]+)'),
                    re.compile('(.*)')
                ]
ip_regex = re.compile('\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}')
data = []

def check_none(line):
    if line == '(none)':
        return 'none'
    else:
        return line

dns_lookup = {}
reverse_lookup = {}

## Get all events
state = 0
element = { 'syslog': [] }

# doing lines this way so that I can rewind when I dont see a line I am looking for, notably ip and user lines
# no longer appear if ossec does not find anything for those lines
fp = report.tell()
line = report.readline()
while line != '':
    #print repr(line) # debug
    if state > 4:
        #print "state %d" % state
        # Need to get /all/ of the syslog entries that correspond to a event match, sometimes more than one
        if len(line) > 1:
            state = 5
            #print repr(line_regex[state].match(line).group(1)) # debug
            element['syslog'].append(line_regex[state].match(line).group(1).replace("\\","\\\\").replace("<","&lt;").replace(">","&gt;"))
        else :
            #print "done line %d!" % linecount
            #print repr(element)+"\n----------" # debug
            element['count'] = 1
            flag = False
            for d in data:
                if d['host'] == element['host']:
                    if d['rule'] == element['rule']:
                        if d['source_ip'] == element['source_ip']:
                            if d['user'] == element['user']:
                                if d['count'] < 15:
                                    d['syslog'].extend(element['syslog'])
                                d['count'] += 1
                                flag = True
            if flag == False:
                data.append(element)
            # Reset!
            state = 0
            element = { 'syslog': [] }
    else:
        #print repr(line_regex[state].match(line).groups()) # debug
        if state == 0:
            #print "state %d" % state
            if len(line) > 1:
                temp = line_regex[state].match(line).group(1)
                # Some tag lines have pesky trailing apostrophes, get rid of them!
                if temp.endswith(','):
                    temp = temp[:-1]
                element['tags'] = temp.split(',')
            else:
                state -= 1
        elif state == 1:
            #print "state %d" % state
            element['host'] = line_regex[state].match(line).group(1)
        elif state == 2:
            #print "state %d" % state
            element['rule'] = int(line_regex[state].match(line).group(1))
            element['level'] = int(line_regex[state].match(line).group(2))
            # Dumb: some of the rule_text's do not have a period, some do, take it away!
            temp = line_regex[state].match(line).group(3)
            if temp.endswith('.'):
                temp = temp[:-1]
            element['rule_text'] = temp
        elif state == 3:
            #print "state %d" % state
            groups = line_regex[state].match(line)
            if groups == None:
                element['source_ip'] = 'none'
                report.seek(fp)
            else:
                found = line_regex[state].match(line).group(1).replace('::ffff:','')
                search = ip_regex.match(found)
                if search != None:
                    # found an ip
                    ip_addr = search.group(0)
                    if DNSDEBUG: dns_lookup[ip_addr] = "debug.localdomain"
                    if ip_addr in dns_lookup:
                        host_name = dns_lookup[ip_addr]
                    else:
                        try:
                            host_name = socket.gethostbyaddr(ip_addr)[0]
                        except socket.herror:
                            host_name = ""
                        dns_lookup[ip_addr] = host_name
                elif '.' in found:
                    # have a hostname
                    host_name = found
                    if DNSDEBUG: reverse_lookup[host_name] = "0.0.0.0"
                    if host_name in reverse_lookup:
                        ip_addr = reverse_lookup[host_name]
                    else:
                        try:
                            ip_addr = socket.gethostbyname(host_name)
                        except socket.gaierror:
                            ip_addr = ""
                        reverse_lookup[ip_addr] = host_name
                else:
                    ip_addr = found
                    host_name = ''
                element['source_ip'] = "%s - (%s)" % (ip_addr, host_name)
                # print "%s - (%s)" % (ip_addr, host_name)
        elif state == 4:
            #print "state %d" % state
            groups = line_regex[state].match(line)
            if groups == None:
                element['user'] = 'none'
                report.seek(fp)
            else:
                element['user'] = check_none(line_regex[state].match(line).group(1))
        
        state += 1
    fp = report.tell()
    line = report.readline()

## Sort

def insert(val, item, data_dict):
    if item not in data_dict:
        data_dict[item] = []
    data_dict[item].append(val)

data_tags = {}
data_levels = {}
data_source_ips = {}
data_rules = {}
data_hosts = {}
data_users = {}
sortedLists = {'data_tags':data_tags,'data_levels':data_levels,'data_source_ips':data_source_ips,'data_rules':data_rules,'data_hosts':data_hosts,'data_users':data_users}

# Go through data array and sort out the similary ones with pointers back to data array
dnum = 0
while dnum < len(data):
    #print data[dnum] # debug
    for tag in data[dnum]['tags']:
        insert(dnum, tag, data_tags)
    insert(dnum, data[dnum]['level'], data_levels)
    insert(dnum, data[dnum]['source_ip'], data_source_ips)
    insert(dnum, data[dnum]['rule'], data_rules)
    insert(dnum, data[dnum]['host'], data_hosts)
    insert(dnum, data[dnum]['user'], data_users)
    dnum += 1

# Cheetah templates for webpage generation
eventpage_template = '''
<html>
<head>
<script type="text/javascript" language="javascript" src="../js/jquery.js"></script> 
<script type="text/javascript" language="javascript" src="../js/jquery.dataTables.js"></script> 
<script type="text/javascript" language="javascript" src="../js/jquery.tufte-graph.js"></script> 
<script type="text/javascript" language="javascript" src="../js/jquery.enumerable.js"></script> 
<script type="text/javascript" language="javascript" src="../js/raphael.js"></script> 

<script type="text/javascript">


\$(document).ready(function() {

   /*
    * Generate graph
    */
    jQuery('#eventgraph').tufteBar({
        data: [
#for $k in sorted($nav.iterkeys())
#set $vlen = len($nav[$k])
            [${vlen}, {label: '$k'}],
#end for
        ],
        barWidth: 0.8,
        barLabel: function(index) { return "<center>"+this[0]+"</center>" },
        axisLabel: function(index) { return "" },
        color: function(index) { 
            return ['#E57536', '#82293B'][index % 2] 
        },
        
    });
   /*
    * Generate tooltips
    */
    \$('#tooltip').hide();
    \$('#eventgraph svg rect').live('click', function (e) {
        /*console.log('we clicked');*/
        window.location = "#"+\$(this).attr('axislabel');
    });
    \$('#eventgraph svg rect').live('mousemove', function (e) {
        /*console.log('we are moving');*/
        var mousetooltip = e.pageX + 25 +\$('#tooltip').width();
        var leftpos = e.pageX + 15;
        if ( mousetooltip > \$(window).width()) {
            leftpos = e.pageX - (mousetooltip-\$(window).width());
        }
        \$('#tooltip').show();
        \$('#tooltip').css({
            top: (e.pageY + 15) + "px",
            left: (leftpos) + "px"
        });
        \$('#tooltip').html(\$(this).attr('axislabel'));
    });
    \$('#eventgraph svg rect').live('mouseout', function (e) {
        /*console.log('we are out');*/
        \$('#tooltip').toggle();
    });
    
    \$('#nav').hide();
    \$('#showmenu').live('click', function (e) {
        \$('#nav').toggle();
    });
    
    /*
     * Initialse DataTables
     */
#for $k in $nav.keys()
#set $kesc = str($k).replace('.','_').replace('-','').replace(':','_').replace('@','_').replace(' ','').replace('(','').replace(')','')
var oTable_$kesc;
    var oTable_$kesc = \$('#event_$kesc').dataTable( {
        "fnRowCallback": function(nRow, aData, iDisplayIndex, iDisplayIndexFull) {
            \$('td:eq(0)', nRow).html('<img src="../images/details_open.png">');
            return nRow;
        },
	    "aoColumnDefs": [
		    { "bSortable": false, "aTargets": [ 0 ] },
	    ],
	    "bPaginate": false,
	    "aaSorting": [[ 2, "asc" ]],
    });

    /* Add event listener for opening and closing details
     * Note that the indicator for showing which row is open is not controlled by DataTables,
     * rather it is done here
     */
    \$('#event_$kesc tbody td').live('click', function () {
	    var nTr = this.parentNode
	    var button = this.parentNode.firstChild.nextSibling.firstChild;
	    if ( button.src.match('details_close') )
	    {
		    /* This row is already open - close it */
		    button.src = "../images/details_open.png";
		    oTable_${kesc}.fnClose( nTr );
	    }
	    else
	    {
		    /* Open this row */
		    button.src = "../images/details_close.png";
		    var element = \$('td:eq(8)', nTr).html()
    	    /*console.log(element);*/
		    oTable_${kesc}.fnOpen( nTr, element, 'details' );
	    }
    } );
#end for

});
</script>

<style type="text/css"> 
@import "../css/demo_page.css";
@import "../css/demo_table.css";
@import "../css/tufte-graph.css";

a:link a:visited a:active a:hover {
    text-decoration: underline;
    color: blue;
}

.event_table {
    width: 100%;
}

#eventgraph {
    margin-top: 50px;
    margin-bottom: 50px;
    height: 200px;
    width: 100%;
}

h2 {
    /*margin-bottom: -30px;*/
}

#nav {
    position: absolute;
    background: grey;
    padding: 20px;
    boder: 1px solid black;
    z-index: 51;
    height: 400px;
    width: 300px;
    overflow:auto;
}

#event_body {
/*    position: absolute;
    left: 410px;*/
}

.hide {
    visibility: hidden;
    position: absolute;
    top: 0px;
    left: 0px;
    height: 0px;
}

.alabel {
    padding-top: 15px;
    padding-left: 5px;
    -webkit-transform: rotate(45deg); 
    -moz-transform: rotate(45deg);
    height: 100px;
}

#tooltip { 
    background: #ff0; 
    padding: 5px; 
    border: 1px solid #ddd; 
    position: absolute; 
    z-index: 50;
}

</style>
</head>
<body>
<a href=index.html>Back to Index</a>
<a id="showmenu" href=#>Show Menu</a>
<div id="tooltip"></div>
<!-- NAV TABLE -->
<div id=nav>

<table>
#for $k in sorted($nav.iterkeys())
<tr><td><a href="#$k">$k</a></td></tr>
#end for
</table>

</div>
<!-- NAV TABLE -->
<!-- EVENT BODY -->
<div id="eventgraph"></div>
<div id="event_body">

#for $k in sorted($nav.iterkeys())
#set $v = $nav[$k]
#set $kesc = str($k).replace('.','_').replace('-','').replace(':','_').replace('@','_').replace(' ','').replace('(','').replace(')','')
<h2>$k</h2>
<a name="$k"></a>
<table id="event_$kesc" class="event_table">
<thead>
<tr>
  <th></th>
  <th>host</th>
  <th>rule</th>
  <th>rule_text</th>
  <th>source_ip</th>
  <th>user</th>
  <th>tags</th>
  <th>count</th>
  <th class=hide>syslog</th>
</tr>
</thead>
<tbody>

#for $val in $v
<tr>
    <td></td>
    <td>$data[$val]['host']</td>
    <td>$data[$val]['rule']</td>
    <td>$data[$val]['rule_text']</td>
    <td>$data[$val]['source_ip']</td>
    <td>$data[$val]['user']</td>
    <td>#slurp
#for $tag in $data[$val]['tags'] 
$tag #slurp
#end for
    </td>
    <td>$data[$val]['count']</td>
    <td class=hide>#slurp
#for $entry in $data[$val]['syslog']
$entry<br> #slurp
#end for
    </td>
</tr>
#end for

</tbody>
</table>
#end for

</div>
<!-- EVENT BODY -->
Page generated at #echo $datetime.today()
</body>
</html>
'''

mainpage_template = '''
<html>
<body>
<h2>Reports available:</h2>
<ul>
#for $list in $sortedLists
<li><a href=${list}.html>By $list</a></li>
#end for
</ul>
Page generated at #echo $datetime.today()
</body>
</html>
'''

#'data_tags':data_tags,
#'data_levels':data_levels,
#'data_source_ips':data_source_ips,
#'data_rules':data_rules,
#'data_hosts':data_hosts

# Generate the webpages and store them
for name,table in sortedLists.items():
    ns = { 'datetime': datetime, 'data':data, 'nav':table }
    t = Template(eventpage_template, searchList=[ns])
    f = open(opts['directory']+"/"+name+'.html', 'w+')
    f.write(str(t))
    f.close()

mainpage_ns = { 'datetime': datetime, 'sortedLists':sortedLists }
t = Template(mainpage_template, searchList=[mainpage_ns])
f = open(opts['directory']+'/index.html', 'w+')
f.write(str(t))
f.close()














