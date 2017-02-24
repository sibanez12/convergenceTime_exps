
import sys, re

def parse_tcpprobe_file(tcpprobeLog, srcIP, dstIP, port):
    """
    Processes a tcp probe output file and returns a list of tuples:
      (src, dst, time, sent_bytes, acked_bytes, cwnd, srtt)
      
    File looks like this:
2.088625684 172.31.8.176:48068 172.31.6.120:5100 32 0xdbd7ccfc 0xdbd4eee3 45 45 204032 257 26884
2.088698571 172.31.8.176:48068 172.31.6.120:5100 32 0xdbd8c1af 0xdbd5e396 45 45 204032 254 26884
2.088744071 172.31.8.176:48068 172.31.6.120:5100 32 0xdbd8c1af 0xdbd66f6a 45 45 204032 252 26884
2.088806980 172.31.8.176:48068 172.31.6.120:5100 32 0xdbd9b662 0xdbd74128 45 45 204032 255 26884
2.088868736 172.31.8.176:48068 172.31.6.120:5100 32 0xdbdaab15 0xdbd7ccfc 45 45 204032 258 26884

    fields are printed in the kernel:
        timestamp, src, dst, packet length (TCP), snd_nxt, snd_una, snd_cwnd, 
        ssthresh, snd_wnd, srtt, rcv_wnd
    
    note that the socket state is logged BEFORE processing the ack whose 
      timestamp appears on the left, so the state difference between two lines
      should be attributed to the PRIOR ack. 
    """

    file_contents = open(tcpprobeLog).read().splitlines()
    
    results = []
    state = {}
    
    for line in file_contents:
        
        t, src, dst, pkt_len, snd_nxt, snd_una, snd_cwnd, ssthresh, snd_wnd, \
            srtt, rcv_wnd = line.split(" ")

        # only get the info for a particular src, dst pair
        if ((srcIP not in src) or (dstIP not in dst) or (str(port) not in dst)):
            continue

        # decode fields
        t = float(t)
        pkt_len = int(pkt_len)
        snd_nxt = int(snd_nxt, 16)
        snd_una = int(snd_una, 16)
        snd_cwnd = int(snd_cwnd)
        srtt = int(srtt)
        
        prev_state = state.get( (src, dst), None )
        if prev_state is not None:
            prev_t, prev_snd_nxt, prev_snd_una = prev_state
            sent_bytes = (snd_nxt - prev_snd_nxt) & 0xFFFFFFFF
            acked_bytes = (snd_una - prev_snd_una) & 0xFFFFFFFF
            if sent_bytes > 0x7FFFFFFF or acked_bytes > 0x7FFFFFFF:
                raise RuntimeError("negative changes to snd_nxt or snd_una not supported")
            results.append( (src, dst, prev_t, 
                             (snd_nxt - prev_snd_nxt) & 0xFFFFFFFF,
                             (snd_una - prev_snd_una) & 0xFFFFFFFF, 
                             snd_cwnd, srtt) )
            
        state[ (src, dst) ] = (t, snd_nxt, snd_una)
    
    return results


def get_tcpprobe_stats(tcpprobeLog, srcIP, dstIP, port):
    SUMMARY_INTERVALS_PER_SECOND = 1000  #1000
    summary = {}
                    
    try:
        tuples=parse_tcpprobe_file(tcpprobeLog, srcIP, dstIP, port)
    except:
        print >> sys.stderr, "Could not parse: ", tcpprobeLog
        sys.exit(1)   
 
    for src, dst, t, sent_bytes, acked_bytes, cwnd, srtt in tuples:
        # summary interval
        t = int(t * SUMMARY_INTERVALS_PER_SECOND) / float(SUMMARY_INTERVALS_PER_SECOND)
        # get previous statistics
        prev_sent_bytes, prev_acked_bytes, prev_cwnd, prev_srtt = summary.get(t, (0, 0, 0, 0))
        summary[t] = (prev_sent_bytes + sent_bytes, 
                      prev_acked_bytes + acked_bytes,
                      cwnd, srtt)
    
    time = []
    rate = []
    cwnd = []
    srtt = []
    # write summary
    for t, (sent_bytes, acked_bytes, cwndSamp, srttSamp) in sorted(summary.items()):
        time.append(t)
        interval = 1.0 / SUMMARY_INTERVALS_PER_SECOND
        rate.append(acked_bytes * 8 / (interval * (10.0**9)))
        cwnd.append(cwndSamp)
        srtt.append(srttSamp)
    init_time = time[0]
    time = [t - init_time for t in time]
    return time, rate, cwnd, srtt


def get_tcpprobe_cwnd_srtt(tcpprobeLog, srcIP, dstIP, port):
    try:
        tuples=parse_tcpprobe_file(tcpprobeLog, srcIP, dstIP, port)
    except:
        print >> sys.stderr, "Could not parse: ", tcpprobeLog
        sys.exit(1)

    time = []
    cwnd_vec = []
    srtt_vec = []
    for src, dst, t, sent_bytes, acked_bytes, cwnd, srtt in tuples:
        time.append(t)
        cwnd_vec.append(cwnd)
        srtt_vec.append(srtt)
    init_time = time[0]
    time = [t - init_time for t in time]
    return time, cwnd_vec, srtt_vec






