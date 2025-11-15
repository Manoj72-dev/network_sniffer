import socket
import struct
import threading
import dash
from dash import dash_table, dcc, html
from dash.dependencies import Input, Output
import plotly.graph_objs as go

packets_data = []
packets_stats = {'TCP': 0, 'UDP': 0, 'IGMP': 0, 'Other': 0}


def capture_packets():
    host = socket.gethostbyname(socket.gethostname())
    conn = socket.socket(socket.AF_INET, socket.SOCK_RAW, socket.IPPROTO_IP)
    conn.bind((host, 0))
    conn.setsockopt(socket.IPPROTO_IP, socket.IP_HDRINCL, 1)
    conn.ioctl(socket.SIO_RCVALL, socket.RCVALL_ON)

    while True:
        try:
            raw_data, addr = conn.recvfrom(65536)
            version, header_length, ttl, proto, src, target, data = ipv4_packet(raw_data)
            packet_info = {
                'version': version,
                'header_length': header_length,
                'ttl': ttl,
                'proto': None,
                'src': src,
                'target': target,
                'src_port': None,
                'dest_port': None,
                'info': None
            }

            if proto == 6:
                src_port, dest_port, sequence, acknowledgment, flag_urg, flag_ack, flag_psh, flag_rst, flag_syn, flag_fin, data = tcp_segment(
                    data)
                packet_info.update({
                    'proto': 'TCP',
                    'src_port': src_port,
                    'dest_port': dest_port,
                    'info': f'Sequence- {sequence} , Acknowledgment- {acknowledgment} , Flags- URG: {flag_urg} ACK: {flag_ack} PUS: {flag_psh} RST: {flag_rst} SYN: {flag_syn} FIN: {flag_fin}\0'
                })
                packets_stats['TCP'] += 1

            elif proto == 17:
                src_port, dest_port, size, data = udp_segment(data)
                packet_info.update(
                    {'proto': 'UDP', 'src_port': src_port, 'dest_port': dest_port, 'info': f'size - {size}'})
                packets_stats['UDP'] += 1

            elif proto == 2:
                packet_info.update({'proto': 'IGMP'})
                packets_stats['IGMP'] += 1

            else:
                packets_stats['Other'] += 1

            packets_data.append(packet_info)
            if len(packets_data) > 100:
                packets_data.pop(0)  

        except Exception as e:
            print(f"Error: {e}")


def ipv4_packet(data):
    version_header_length = data[0]
    version = version_header_length >> 4
    header_length = (version_header_length & 15) * 4
    ttl, proto, src, target = struct.unpack('! 8x B B 2x 4s 4s', data[:20])
    return version, header_length, ttl, proto, ipv4(src), ipv4(target), data[header_length:]


def ipv4(addr):
    return '.'.join(map(str, addr))


def tcp_segment(data):
    sec_port, dest_port, sequence, acknowledgment, offset_reserved_flags = struct.unpack('! H H L L H', data[:14])
    offset = (offset_reserved_flags >> 12) * 4
    flag_urg = (offset_reserved_flags & 32) >> 5
    flag_ack = (offset_reserved_flags & 16) >> 4
    flag_psh = (offset_reserved_flags & 8) >> 3
    flag_rst = (offset_reserved_flags & 4) >> 2
    flag_syn = (offset_reserved_flags & 2) >> 1
    flag_fin = offset_reserved_flags & 1
    return sec_port, dest_port, sequence, acknowledgment, flag_urg, flag_ack, flag_psh, flag_rst, flag_syn, flag_fin, data[offset:]


def udp_segment(data):
    src_port, dest_port, size = struct.unpack('! H H 2x H', data[:8])
    return src_port, dest_port, size, data[8:]


app = dash.Dash(__name__)

app.layout = html.Div(style={'backgroundColor': '#c3c3de', 'padding': '15px'}, children=[
    html.Div([
        html.Div(
            dcc.Graph(
                id='packets-bar-graph',
                style={
                    'height': '370px',
                    'width': '100%',
                    'border': '2px solid #000000',
                    'borderRadius': '10px',
                    'boxShadow': '5px 5px 15px rgba(0, 0, 0, 0.3)',
                    'backgroundColor': '#ffffff'
                }
            ),
            style={'width': '48%', 'display': 'inline-block', 'verticalAlign': 'top','marginLeft': '0.7%', 'marginRight': '1%'}
        ),
        html.Div(
            dcc.Graph(
                id='packets-pie-graph',
                style={
                    'height': '370px',
                    'width': '100%',
                    'border': '2px solid #000000',
                    'borderRadius': '10px',
                    'boxShadow': '5px 5px 15px rgba(0, 0, 0, 0.3)',
                    'backgroundColor': '#ffffff'
                }
            ),
            style={'width': '48%', 'display': 'inline-block', 'verticalAlign': 'top', 'marginLeft': '1%'}
        )
    ], style={'justify-content': 'space-between', 'padding': '5px'}),
    html.Div([
        dash_table.DataTable(
            id='table',
            columns=[
                {'name': 'Version', 'id': 'version'},
                {'name': 'Header Length', 'id': 'header_length'},
                {'name': 'TTL', 'id': 'ttl'},
                {'name': 'Protocol', 'id': 'proto'},
                {'name': 'Source IP', 'id': 'src'},
                {'name': 'Destination IP', 'id': 'target'},
                {'name': 'Source Port', 'id': 'src_port'},
                {'name': 'Destination Port', 'id': 'dest_port'},
                {'name': 'Info', 'id': 'info'}
            ],
            data=[],
            style_table={
                'height': '363px',
                'width': '98%',
                'overflowY': 'auto',
                'border': '2px solid #000000',
                'borderRadius': '10px',
                'boxShadow': '5px 5px 15px rgba(0, 0, 0, 0.3)',
                'margin': '10px',
                'backgroundColor': '#ffffff'
            },
            style_header={
                'backgroundColor': '#f8f9fa',
                'fontWeight': 'bold',
                'textAlign': 'center',
                'color': '#333333'
            },
            style_cell={'textAlign': 'center', 'padding': '10px', 'color': '#555555'},
            fixed_rows={'headers': True},
            style_data_conditional=[
                {
                    'if': {'row_index': 'odd'},
                    'backgroundColor': '#f1f3f5'
                }
            ]
        )
    ]),

    dcc.Interval(
        id='interval-component',
        interval=400,
        n_intervals=0
    )
])


@app.callback(
    [Output('table', 'data'),
     Output('packets-bar-graph', 'figure'),
     Output('packets-pie-graph', 'figure')],
    [Input('interval-component', 'n_intervals')],
    prevent_initial_call=True
)
def update_table_and_graph(n_intervals):
    bar_figure = {
        'data': [
            go.Bar(x=list(packets_stats.keys()), y=list(packets_stats.values()),
                   marker=dict(color=['#636EFA', '#EF553B', '#00CC96', '#AB63FA']))
        ],
        'layout': {
            'title': 'No. of each protocols',
            'xaxis': {'title': 'Protocol'},
            'yaxis': {'title': 'Count'},
            'plot_bgcolor': 'rgba(0,0,0,0)',
            'paper_bgcolor': 'rgba(0,0,0,0)',
            'font': {'color': 'black'},
        }
    }

    pie_figure = {
        'data': [
            go.Pie(labels=list(packets_stats.keys()), values=list(packets_stats.values()), 
                   marker=dict(colors=['#636EFA', '#EF553B', '#00CC96', '#AB63FA']),
                   hole=0.3)
        ],
        'layout': {
            'title': 'Protocol Distribution',
            'plot_bgcolor': 'rgba(0,0,0,0)',
            'paper_bgcolor': 'rgba(0,0,0,0)',
            'font': {'color': 'black'},
            'margin': {'l': 20, 'r': 20, 'b': 20, 't': 50},
            'height': 350, 
        }
    }

    return packets_data, bar_figure, pie_figure


def run_dash():
    app.run_server(debug=True)


if __name__ == '__main__':
    threading.Thread(target=capture_packets).start()
    run_dash()
    
