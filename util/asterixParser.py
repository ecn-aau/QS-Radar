import array
import matplotlib.pyplot as plt
from datetime import datetime
import numpy as np

from dataPlotter import plot_time_deltas_ccdf

dataItems = [["['010']", 0, 0],
             ["['015']", 0, 0],
             ["['070']", 0, 0],
             ["['105']", 0, 0],
             ["['100']", 0, 0],
             ["['060']", 0, 0],
             ["['380']", 0, 0],
             ["['080']", 0, 0],
             ["['200']", 0, 0],
             ["['136']", 0, 0],
             ["['130']", 0, 0],
             ["['220']", 0, 0],
             ["['390']", 0, 0],
             ["['270']", 0, 0],
             ["['300']", 0, 0],
             ["['110']", 0, 0],
             ["['500']", 0, 0],]

intervals = [[0, 400, 0],
             [401, 800, 0],
             [801, 1200, 0],
             [1201, 1600, 0],
             [1601, 2000, 0],
             [2001, 2400, 0],
             [2401, 2800, 0],
             [2801, 3200, 0],
             [3201, 3600, 0],
             [3601, 4000, 0],
             [4001, 4400, 0],
             [4401, 4800, 0],
             [4801, 5200, 0],]

max_timestamps = 10000

def mySum(records_length):
    cum_sum = 0
    num: int
    for num in records_length:
        cum_sum = cum_sum + num
    return cum_sum

def createIntervalLabels():
    labels = []
    for interval in intervals:
        labels.append(f"{interval[0]}- \n {interval[1]}")
    return labels

def parse_file(name):
    print(f'Hi, parsing {name}')

    records_length = []
    timestamps = []
    currentCountOfTimestamp = 0
    max_timestamps_achived = False
    # Replace 'your_file.txt' with the path to your file
    with open(name, 'r', encoding='utf-8', errors='ignore') as file:
        for line in file:
            if max_timestamps_achived:
                continue  # reached required timestamps number

            trailedline = line.lstrip().rstrip()
            if trailedline.startswith('record:'):
                # record found; get the length
                tokens = trailedline.split(",")  # Split by comma
                # 1st token is "record: len=xxx bytes
                try:
                    st = len(str('record:'))
                    end = len(tokens[0]) - len(str('bytes:'))
                    ttk = tokens[0][st: end].lstrip().rstrip()[len(str('len=')): end]
                    length = int(ttk.lstrip().rstrip())
                    records_length.append((length, currentCountOfTimestamp))
                except ValueError as e:
                    print(f"Conversion failed: {e}")
            else:
                if trailedline.startswith('timestamp:'):
                    if len(timestamps) == max_timestamps:
                        max_timestamps_achived = True
                        continue
                    #timestamp: 2025-07-07  11:08:01.179298 + 00:00
                    tokens = trailedline.split(" ")  # Split by space
                    dt_string=str(tokens[1])+ " " + str(tokens[2][0:len(tokens[2])-len("+00:00")])
                    # Parse into a datetime object
                    dt_object = datetime.strptime(dt_string, '%Y-%m-%d  %H:%M:%S.%f')
                    timestamps.append(dt_object)
                    currentCountOfTimestamp = len(timestamps) - 1
                else:
                    for item in dataItems:
                        if trailedline.startswith(item[0]):
                            tokens = trailedline.split(",")  # Split by comma
                            fieldlength = int(tokens[1][len(str(' len=')): len(tokens[1]) - len(str(' bits'))].lstrip().rstrip())
                            item[1] = item[1] + 1
                            item[2] = item[2] + fieldlength
                            break

    print("Records:", len(records_length))
    count = 0
    sum_records = 0
    for item in records_length:
        count += 1
        sum_records += item[0]
    allBytes = sum_records

    # printouts for checking the output: all bytes processed (payload only), average bytes per track, standard deviation of track size with respect to average, no of datagrams processed
    print("All bytes:", allBytes)
    averageTrack = allBytes / len(records_length)
    print("Average Track Size(mean): ", averageTrack, "bytes")
    print("Standard deviation tracks:", np.std(records_length[0]))
    print("Timestamps in all (datagrams):", len(timestamps))

    # printout of data items encounters in the whole track pool
    # each track has a random selection of data items, and this printout demonstrates the diversity of the content of the tracks generated
    for item in dataItems:
        afz = f"{item[2] / (8 * item[1]):.2f}"
        print("Item type: ", item[0], " encountered in ", item[1], "out of ", len(records_length), "records", "Total bytes ", item[2] / 8, "Average field size: ", afz, " bytes")

    # overall average throughput rate
    dt = timestamps[len(timestamps) - 1] - timestamps[0]
    averagethroughput = allBytes / dt.total_seconds()
    print("Average throughput per second:", averagethroughput, "bytes")

    currentCountOfTimestamp = 0
    throughputPerTimestamp = 0
    throughputBetweenTimestamps = []
    rateBetweenTimestamps = []
    lasttimestamp = timestamps[0]

    # aggregate the throughput per timestamp
    for item in records_length:
        if item[1] ==currentCountOfTimestamp:
            throughputPerTimestamp += item[0]
        else:
            throughputBetweenTimestamps.append((timestamps[currentCountOfTimestamp], throughputPerTimestamp))
            dt = (timestamps[currentCountOfTimestamp] - lasttimestamp).total_seconds()
            if dt > 0:
                rateBetweenTimestamps.append((timestamps[currentCountOfTimestamp], throughputPerTimestamp/dt))
            lasttimestamp =  timestamps[currentCountOfTimestamp]
            currentCountOfTimestamp += 1
            throughputPerTimestamp = 0

    # append last record
    throughputBetweenTimestamps.append((timestamps[currentCountOfTimestamp], throughputPerTimestamp))
    dt = (timestamps[currentCountOfTimestamp] - lasttimestamp).total_seconds()
    rateBetweenTimestamps.append((timestamps[currentCountOfTimestamp], throughputPerTimestamp/dt))

    #plot barchart throughput per timestamp
    values = ([item[1] for item in throughputBetweenTimestamps])
    labels = createArray(len(throughputBetweenTimestamps),0, True)
    p1 = plotBarChart(labels, values, "Throughput per timestamp", "timestamps", "throughput (bytes)")

    extractThroughputBetweenTimestampsIntervals(throughputBetweenTimestamps)
    values = ([item[2] for item in intervals])
    labels = createIntervalLabels()
    p2 = plotBarChart(labels, values, "", "Payload size", "Count")
    p2_2 = plot_time_deltas_ccdf(
        [x[1] for x in throughputBetweenTimestamps],
        title="CCDF of ASTERIX payload sizes",
        xlabel="Payload size (bytes)",
        save_path="payload_size.pdf",
        percentiles=[50,90,99],
        log_y=True)

    p3 = plotFrequency(len(records_length))

    labels = createArray(len(rateBetweenTimestamps),0, True)
    values = ([item[1] for item in rateBetweenTimestamps])
    p4 = plotBarChart(labels, values, "Data rate between timestamps", "timestamps", "rate (bytes/second)")

    plt.show()

# the function groups the ThroughputBetweenTimestamps per intervals
def extractThroughputBetweenTimestampsIntervals(throughputBetweenTimestamps):
    for item in throughputBetweenTimestamps:
        for interval in intervals:
            if interval[0] <= item[1] <= interval[1]:
                interval[2] = interval[2] + 1
                continue

def plotFrequency(size):
    labels = ([item[0] for item in dataItems])
    frequency = ([item[1] for item in dataItems])

    # Create bar chart
    plt.bar(labels, frequency)
    plt.plot(labels, createArray(len(labels), size, False), color='red', marker='o', label='All records')

    # Add titles and labels
    plt.title('Frequency of ASTERIX fields in records')
    plt.xlabel('Fields')
    plt.ylabel('Frequency')

    # Show the plot
    plt.figure()
    plt.show(block= False)

def plotBarChart(labels, values, title, xlabel, ylabel):
    # Create bar chart
    plt.bar(labels, values)

    # Add titles and labels
    plt.title(title)
    plt.xlabel(xlabel)
    plt.ylabel(ylabel)

    # Show the plot
    plt.figure()
    plt.show(block= False)

def plotChart(tpr, title, xlabel, ylabel):
    values = ([item[1] for item in tpr])
    labels = createArray(len(tpr),0, True)

    # Create bar chart
    plt.bar(labels, values)

    # Add titles and labels
    plt.title(title)
    plt.xlabel(xlabel)
    plt.ylabel(ylabel)

    plt.figure()
    plt.show(block= False)

def createArray(size, value, increasing:False ):
    myArray = array.array('i', [])
    for i in range(size):
        if increasing:
            myArray.append(i)
        else:
            myArray.append(value)
    return myArray


# Press the green button in the gutter to run the script.
if __name__ == '__main__':
    parse_file('../data/ASTERIX/ast_log_full.txt')

