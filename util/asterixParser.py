import array
import numpy as np
import matplotlib.pyplot as plt
from datetime import datetime

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
             ["['500']", 0, 0]]


def mySum(records_length):
    cum_sum = 0
    num: object
    for num in records_length:
        cum_sum = cum_sum + num
    return cum_sum


def parse_file(name):
    records_length = [];
    timestamps = [];
    currentCountOfTimestamp = 0;
    # Replace 'your_file.txt' with the path to your file
    with open(name, 'r', encoding='utf-8', errors='ignore') as file:
        for line in file:
            trailedline = line.lstrip().rstrip();
            if (trailedline.startswith('record:')):
                # record found; get the length
                tokens = trailedline.split(",")  # Split by comma
                # 1st token is "record: len=xxx bytes
                try:
                    st = len(str('record:'));
                    end = len(tokens[0]) - len(str('bytes:'));
                    ttk = tokens[0][st: end].lstrip().rstrip()[len(str('len=')): end];
                    # ttk = tk[len(str('len=')): end];
                    length = int(ttk.lstrip().rstrip())
                    records_length.append((length, currentCountOfTimestamp))
                except ValueError as e:
                    print(f"Conversion failed: {e}")
            else:
                a = 0
                if(trailedline.startswith('timestamp:')):
                    #timestamp: 2025-07-07  11:08:01.179298 + 00:00
                    tokens = trailedline.split(" ")  # Split by space
                    dt_string=str(tokens[1])+ " " + str(tokens[2][0:len(tokens[2])-len("+00:00")])
                    # Parse into a datetime object
                    dt_object = datetime.strptime(dt_string, '%Y-%m-%d  %H:%M:%S.%f')
                    timestamps.append(dt_object)
                    currentCountOfTimestamp = len(timestamps) - 1;
                else:
                    for item in dataItems:
                        if trailedline.startswith(item[0]):
                            tokens = trailedline.split(",")  # Split by comma
                            st = len(str(' len='));
                            end = len(tokens[1]) - len(str(' bits'));
                            tk = tokens[1][st: end].lstrip().rstrip();
                            fieldlength = int(tk.lstrip().rstrip());
                            item[1] = item[1] + 1;
                            item[2] = item[2] + fieldlength;
                            break

    print("Records:", len(records_length));
    count = 0
    sum = 0
    for item in records_length:
        # print("# " + str(count) + " Length: " + str(item[0]) + " bytes")
        count += 1;
        sum += item[0];
    # allBytes =  #mySum(records_length[0]);
    allBytes = sum
    print("All bytes:", allBytes);
    averageTrack = allBytes / len(records_length);
    print("AverageTrackSize:", averageTrack, "bytes");
    print("Timestamps in all (datagrams):", len(timestamps));

    for item in dataItems:
        print("Item type: ", item[0], " encountered in ", item[1], "out of ", len(records_length), "records", "Total bytes ", item[2] / 8, "Average field size: ", item[2] / (8 * item[1]), " bytes");

#    for item in timestamps:
#        print("Timestamp: ", item.strftime("%Y-%m-%d %H:%M:%S.%f"));

    # overall average throughtput rate
    dt = timestamps[len(timestamps) - 1] - timestamps[0];
    averagethroughput = allBytes / dt.total_seconds();
    print("Average throughput per second:", averagethroughput, "bytes");

    currentCountOfTimestamp = 0
    throughtputPerTimestamp = 0;
    throughputBetweenTimestamps = [];
    rateBetweenTimestamps = [];
    lasttimestamp = timestamps[0];

    # aggregate the throughput per timestamp
    for item in records_length:
        if item[1] ==currentCountOfTimestamp:
            throughtputPerTimestamp += item[0]
        else:
            throughputBetweenTimestamps.append((timestamps[currentCountOfTimestamp], throughtputPerTimestamp));
            dt = (timestamps[currentCountOfTimestamp] - lasttimestamp).total_seconds();
            if(dt > 0):
                rateBetweenTimestamps.append((timestamps[currentCountOfTimestamp], throughtputPerTimestamp/dt));
            lasttimestamp =  timestamps[currentCountOfTimestamp];
            currentCountOfTimestamp += 1;
            throughtputPerTimestamp = 0;

    # append last record
    throughputBetweenTimestamps.append((timestamps[currentCountOfTimestamp], throughtputPerTimestamp));
    dt = (timestamps[currentCountOfTimestamp] - lasttimestamp).total_seconds();
    rateBetweenTimestamps.append((timestamps[currentCountOfTimestamp], throughtputPerTimestamp/dt));

    #plot barchart througput per timestamp
    plotChart(throughputBetweenTimestamps, "throughput per timestamps", "timestamps", "throughput (bytes)")

    plotFrequency(len(records_length));

    plotChart(rateBetweenTimestamps, "rate between timestamps", "timestamps", "rate (bytes/second)")



def plotFrequency(size):
    labels = ([item[0] for item in dataItems]);
    # .append("All"));
    frequency = ([item[1] for item in dataItems]);
    # .append(int(size));

    # Create bar chart
    plt.bar(labels, frequency)
    plt.plot(labels, createArray(len(labels), size, False), color='red', marker='o', label='All records')

    # Add titles and labels
    plt.title('Simple Bar Chart')
    plt.xlabel('Fields')
    plt.ylabel('Frequency')

    # Show the plot
    plt.show()

def plotChart(tpr, title, xlabel, ylabel):
    #labels = ([item[0] for item in tpr]);
    values = ([item[1] for item in tpr]);
    labels = createArray(len(tpr),0, True);

    # Create bar chart
    plt.bar(labels, values)

    # Add titles and labels
    plt.title(title)
    plt.xlabel(xlabel)
    plt.ylabel(ylabel)

    # Show the plot
    plt.show()


def createArray(size, value, increasing:False ):
    myArray = array.array('i', []);
    for i in range(size):
        if(increasing):
            myArray.append(i)
        else:
            myArray.append(value)
    return myArray


if __name__ == '__main__':
    parse_file('logs/ast_log_full.txt')
    # parse_file('logs/ast_log.txt')

