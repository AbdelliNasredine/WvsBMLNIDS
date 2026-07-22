##! Per-connection TCP flag counts, appended to conn.log.
##!
##! Zeek's conn.log reports per-direction packet/byte counts and a `history`
##! string, but not per-direction flag COUNTS. This script tallies them from the
##! tcp_packet event so the canonical schema can be populated for Zeek on equal
##! footing with NFStream / CICFlowMeter. ECE/CWR are not exposed by the flags
##! string here and are left unset (-> <NA> in canonical), which is itself a
##! documented cross-tool divergence.

@load base/protocols/conn

module FlowFeat;

export {
    redef record Conn::Info += {
        s_syn: count &log &optional;
        s_fin: count &log &optional;
        s_rst: count &log &optional;
        s_psh: count &log &optional;
        s_ack: count &log &optional;
        s_urg: count &log &optional;
        r_syn: count &log &optional;
        r_fin: count &log &optional;
        r_rst: count &log &optional;
        r_psh: count &log &optional;
        r_ack: count &log &optional;
        r_urg: count &log &optional;
    };
}

type Flags: record {
    s_syn: count &default=0; s_fin: count &default=0; s_rst: count &default=0;
    s_psh: count &default=0; s_ack: count &default=0; s_urg: count &default=0;
    r_syn: count &default=0; r_fin: count &default=0; r_rst: count &default=0;
    r_psh: count &default=0; r_ack: count &default=0; r_urg: count &default=0;
};

global tbl: table[string] of Flags;

event tcp_packet(c: connection, is_orig: bool, flags: string,
                 seq: count, ack: count, len: count, payload: string)
{
    if ( c$uid !in tbl )
        tbl[c$uid] = Flags();
    local f = tbl[c$uid];
    if ( is_orig )
    {
        if ( "S" in flags ) ++f$s_syn;
        if ( "F" in flags ) ++f$s_fin;
        if ( "R" in flags ) ++f$s_rst;
        if ( "P" in flags ) ++f$s_psh;
        if ( "A" in flags ) ++f$s_ack;
        if ( "U" in flags ) ++f$s_urg;
    }
    else
    {
        if ( "S" in flags ) ++f$r_syn;
        if ( "F" in flags ) ++f$r_fin;
        if ( "R" in flags ) ++f$r_rst;
        if ( "P" in flags ) ++f$r_psh;
        if ( "A" in flags ) ++f$r_ack;
        if ( "U" in flags ) ++f$r_urg;
    }
    tbl[c$uid] = f;
}

event connection_state_remove(c: connection)
{
    if ( c$uid !in tbl )
        return;
    local f = tbl[c$uid];
    c$conn$s_syn = f$s_syn; c$conn$s_fin = f$s_fin; c$conn$s_rst = f$s_rst;
    c$conn$s_psh = f$s_psh; c$conn$s_ack = f$s_ack; c$conn$s_urg = f$s_urg;
    c$conn$r_syn = f$r_syn; c$conn$r_fin = f$r_fin; c$conn$r_rst = f$r_rst;
    c$conn$r_psh = f$r_psh; c$conn$r_ack = f$r_ack; c$conn$r_urg = f$r_urg;
    delete tbl[c$uid];
}
