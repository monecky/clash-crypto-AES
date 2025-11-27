import pandas as pd
import os

file_path = "output_times.txt"
try:
    os.path.exists(file_path)
except:
    print("Run the program in its dedicated folder, or ensure file_path includes the correct path from your current working directory.")
# Remove the file if it exists
if os.path.exists(file_path):
    os.remove(file_path)
    print(f"{file_path} has been removed.")
else:
    print(f"{file_path} does not exist. It will be created and used accordingly")
# How many tests per AES algorithm
number_tests = 100
df = pd.read_csv("digital.csv")
df["start_time"] = pd.to_datetime(df["start_time"])
main_async = df[df["name"] == "Async Serial"].copy()
sub_async = df[df["name"] == "Async Serial [1]"].copy()

main_async = main_async.sort_values("start_time")
sub_async = sub_async.sort_values("start_time")
time_differences = []


for index, row in df.iterrows():
    for next_index, next_row in df.iterrows():
        if index + 1 == next_index:
            if row["name"] == "Async Serial [1]":
                if next_row["name"] == "Async Serial":
                    delta_us = (next_row['start_time'] - row['start_time']).total_seconds() * 1e6
                    time_differences.append(delta_us)
                    with open(file_path, "a") as f:
                        f.write(f"{delta_us:.3f} µs\n")

AES128 = time_differences[0:number_tests]
AES192 = time_differences[number_tests:2*number_tests]
AES256 = time_differences[2*number_tests:3*number_tests]

# Check if all values are equal
def check_equal(arr, name):
    #  First case covers the standard cycle, the other one covers rounding errors regards floating points.
    if len(set(arr)) == 1 or (len(set(arr)) == 2 and set(arr)[0] in {set(arr)[1] -1,set(arr)[1]+1}) :
        print(f"All durations of {name} are equal")
    else:
        print(f"The durations of {name} differ")
print("")
check_equal(AES128, "AES128")
check_equal(AES192, "AES192")
check_equal(AES256, "AES256")

