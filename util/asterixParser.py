import array
import matplotlib.pyplot as plt

dataItems = [["['010']",0, 0],
             ["['015']",0, 0],
             ["['070']",0, 0],
             ["['105']",0, 0],
             ["['100']",0, 0],
             ["['060']",0, 0],
             ["['380']",0, 0],
             ["['080']",0, 0],
             ["['200']",0, 0],
             ["['136']",0, 0],
             ["['130']",0, 0],
             ["['220']",0, 0],
             ["['390']",0, 0],
             ["['270']",0, 0],
             ["['300']",0, 0],
             ["['110']",0, 0],
             ["['500']",0, 0]]

def mySum(records_length):
    cum_sum = 0
    num: object
    for num in records_length:
        cum_sum += num
    return cum_sum

def parse_file(name):
    print(f'Hi, parsing {name}')

    records_length = []
    count = 0
    # Replace 'your_file.txt' with the path to your file
    with open(name, 'r', encoding='utf-8', errors='ignore') as file:
        for line in file:
            trailedline = line.lstrip().rstrip()
            if(trailedline.startswith('record:')):
                # record found; get the length
                tokens = trailedline.split(",")  # Split by comma
                # 1st token is "record: len=xxx bytes
                try:
                    st = len(str('record:'))
                    end = len(tokens[0]) - len(str('bytes:'))
                    tk = tokens[0][st: end].lstrip().rstrip()
                    ttk = tk[len(str('len=')): end]
                    length = int(ttk.lstrip().rstrip())
                    records_length.append(length)
                except ValueError as e:
                    print(f"Conversion failed: {e}")
            else:
                for item in dataItems:
                    if trailedline.startswith(item[0]):
                        tokens = trailedline.split(",")  # Split by comma
                        st = len(str(' len='))
                        end = len(tokens[1]) - len(str(' bits'))
                        tk = tokens[1][st: end].lstrip().rstrip()
                        fieldlength = int(tk.lstrip().rstrip())
                        item[1] = item[1] +1
                        item[2] = item[2] + fieldlength
                        break

    print("Records:" ,len(records_length))
    allBytes = mySum(records_length)
    print("All bytes:", allBytes)
    averageTrack = allBytes/len(records_length)
    print("AverageTrackSize:", averageTrack , "bytes")

    for item in dataItems:
        print("Item type: ", item[0], " encountered in ", item[1], "out of ", len(records_length), "records")
        print("Total bytes ", item[2]/8, "Average field size: ", item[2]/(8*item[1]) , " bytes")

    plotFrequency(len(records_length))

def plotFrequency(size):
    labels = ([item[0] for item in dataItems])
              #.append("All"))
    frequency = ([item[1] for item in dataItems])
            #.append(int(size))

    # Create bar chart
    plt.bar(labels, frequency)
    plt.plot(labels, createArray(len(labels), size), color='red', marker='o', label='All records')

    # Add titles and labels
    plt.title('Simple Bar Chart')
    plt.xlabel('Fields')
    plt.ylabel('Frequency')

    # Show the plot
    plt.show()

def createArray(size, value):
    myArray = array.array('i', [])
    for i in range(size):
        myArray.append(value)
    return myArray


if __name__ == '__main__':
    parse_file('../data/ASTERIX/ast_log.txt')

