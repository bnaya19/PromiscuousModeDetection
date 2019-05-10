"""
	This is the single-threaded version of the latency detection script. 
"""
import time
import sys
import threading
import numpy as np 
from scapy.all import *
import matplotlib.pyplot as plt
import matplotlib.patches as mpatches
from matplotlib.ticker import MaxNLocator


ICMP_ECHO_REQUEST = 8
MAX_TIMEOUT = 2
# VMWARE_IFACE = "Realtek PCIe FE Family Controller" # Your inteface name
VMWARE_IFACE =  "VMware Virtual Ethernet Adapter for VMnet1"
#SRC_IP = "169.254.57.226" # Your inteface IP
OUTPUT_FIG_NAME = "output.png"
INITIAL_TRASH_AMOUNT = 500
PERIODIC_TRASH_AMOUNT = 100
MEASUREMENTS_NUMBER = 30
NOISE_AMOUNT = 2000
NO_SLEEP=0
SLEEP_BEFORE_PING = 0.1
SLEEP_BEFORE_MEASUREMENT = 0.5
    

def bomb_network(device_ip, amount):
	noise_packet = Ether(dst="aa:aa:aa:aa:aa:aa")/IP(dst=device_ip)/TCP() 
	for i in xrange(amount):
		sendp(noise_packet,  verbose=False, iface=VMWARE_IFACE)
        

def build_icmp_echo_rquest(target_ip):
	request_packet = Ether(dst="ff:ff:ff:ff:ff:ff")
	request_packet /= IP( dst=target_ip) #src=SRC_IP,
	request_packet /= ICMP(type=ICMP_ECHO_REQUEST)
	return request_packet


def single_rtt_measurement(request_packet):
	response_time = None
	start_time = time.time()
	response = srp1(request_packet, timeout=MAX_TIMEOUT, verbose=False, iface=VMWARE_IFACE)
	if response is not None:
		response_time = response.time - start_time
	return response_time


def save_figure(without_noise_list, with_noise_list, fig_name=OUTPUT_FIG_NAME):
	"""
		Saves the figure of a full measurements set.
	"""
	x_axis = range(1,len(without_noise_list)+1)
	plt.plot(x_axis,np.array(without_noise_list),'ro')
	plt.plot(x_axis,np.array(with_noise_list),'bs')
	
	red_patch = mpatches.Patch(color='red', label='Without noise')
	blue_patch = mpatches.Patch(color='blue', label='With noise')
	
	plt.legend(handles=[red_patch, blue_patch])

	plt.xlabel("Measurement Number")
	plt.ylabel("RTT (Seconds)")
	plt.savefig(fig_name)
	#ax = plt.figure().gca()
	#ax.xaxis.set_major_locator(MaxNLocator(integer=True))
	#plt.show()
	plt.close()
	print "Finish drawing {} ".format(fig_name)


def latency_measurement(target_ip, measurement_func, amount=MEASUREMENTS_NUMBER, output_file_name=OUTPUT_FIG_NAME):
	"""
		Fully performs the latency measurement. 
		measurement_func is the function which performs the measurements while the network is noisy.
	"""

	# Start the "control group" measurements while the network is quiet 
	without_noise = ping_measurement(target_ip, amount)
	# Let the subject computer rest for a while to create a full segregation between the tests
	time.sleep(SLEEP_BEFORE_MEASUREMENT)
	# Start the actual experiment 
	with_noise = measurement_func(target_ip, amount)
	# Plot the results
	save_figure(without_noise, with_noise, output_file_name)
	return (without_noise, with_noise)


def ping_measurement(target_ip, amount=MEASUREMENTS_NUMBER, sleep_time=NO_SLEEP):
	""" 
		Simply returns a list of RTTs received from the target.
	"""
	measurment_results = []
	request_packet = build_icmp_echo_rquest(target_ip)
	
	for curr_measurment in xrange(amount):
		time.sleep(sleep_time)
		response_time = single_rtt_measurement(request_packet)
		if response_time is not None:
			measurment_results.append(response_time)
	return measurment_results


def single_threaded_measurement(target_ip, amount=MEASUREMENTS_NUMBER):
	"""
		This function performs the single threaded latency test in a noisy network. 
		It uses a single thread to both trash the network and to perform the measurement. 
		The big advantage of this version is that no thread switch could occure.
		In the multi-threaded version- while we are waiting for the icmp echo response and 
		our timer is ticking there could be a thread switch to the trashing thread- which 
		can affect the reliability of the results and can cause outliers.
	"""
	measurment_results = []
	request_packet = build_icmp_echo_rquest(target_ip)

	bomb_network(target_ip, INITIAL_TRASH_AMOUNT)

	for curr_measurment in xrange(amount):
		bomb_network(target_ip, PERIODIC_TRASH_AMOUNT)
		response_time = single_rtt_measurement(request_packet)
		if response_time is not None:
			measurment_results.append(response_time)
	return measurment_results


def multi_threaded_measurement(target_ip, amount=MEASUREMENTS_NUMBER):
	"""
		This function performs the multi-threaded latency test in a noisy network. 
		It uses a two threads. One to trash the network and the other to perform the measurement. 
		The advantages of this version is that while the icmp echo requests are waiting for response
		the subject computer continue to receive trash packets so it doesn't have time to "rest".
		In the single-thread approach- while the target havn't return an ICMP response- he will 
		not be bothered and can deal with the trash he got so far. In the multi-threaded approach
		even if we are waiting for response- we will still trash the network and cause the subject
		further latency.
	"""
	noise_thread = threading.Thread(target=bomb_network,args=(target_ip, NOISE_AMOUNT))
	noise_thread.start()
	# Let the noise thread work a bit and create a load on the target before we start to measure the RTTs
	time.sleep(SLEEP_BEFORE_MEASUREMENT)
	with_noise = ping_measurement(target_ip, sleep_time=SLEEP_BEFORE_PING)
	noise_thread.join()
	return with_noise


def main():
	target_ip = sys.argv[1]
	latency_measurement(target_ip, single_threaded_measurement, output_file_name="single_threaded.png")
	latency_measurement(target_ip, multi_threaded_measurement, output_file_name="multi_threaded.png")


if __name__ == '__main__':
    main()