import pandas as pd
import os
# The nessary file paths.
file_path = "output_times.txt"
csv_path = "digital.csv"

# Remove output file if it exists
if os.path.exists(file_path):
    os.remove(file_path)
    print(f"{file_path} has been removed.")
else:
    print(f"{file_path} does not exist. It will be created and used accordingly")

# Read CSV with datetime column parsed
df = pd.read_csv(csv_path, parse_dates=["start_time"])


start_next = df["start_time"].shift(-1)
cond = (
    (df["name"] == "Async Serial [1]") &
    (df["name"].shift(-1) == "Async Serial")
)

delta = start_next[cond] - df.loc[cond, "start_time"]
time_differences = (
    ((delta / pd.Timedelta(microseconds=0.001))/1000) 
    .dropna()                             
    .astype(float)
    .tolist()
)

# -------------------------------------------------------------
# WRITE OUTPUT
# -------------------------------------------------------------
with open(file_path, "w") as f:
    for us in time_differences:
        f.write(f"{us:.3f}\n")

# -------------------------------------------------------------
# READ BACK OUTPUT
# -------------------------------------------------------------
with open(file_path, "r") as f:
    time_differences = [float(line.strip()) for line in f if line.strip()]

# -------------------------------------------------------------
# SPLIT INTO AES TEST GROUPS
# -------------------------------------------------------------
number_tests = 100
AES128 = time_differences[0:number_tests]
AES192 = time_differences[number_tests:2*number_tests]
AES256 = time_differences[2*number_tests:3*number_tests]

# -------------------------------------------------------------
# CHECK FUNCTION
# -------------------------------------------------------------
def check_equal(arr, name):
    diff = max(arr) - min(arr)
    if diff <= 1:
        print(f"All durations of {name} are equal, with delta of 1 µs")
        print(f"The exact difference is {diff:.3f} µs")
        return

    print(f"The durations of {name} differ with {diff:.3f} µs")

print("The .csv is created by exporting the table of data obtained from the logic anlyser and the software Logic 2 and the test is run with `cabal run -- hitlt -p AES`")

# -------------------------------------------------------------
# RUN CHECKS
# -------------------------------------------------------------
check_equal(AES128, "AES128")
check_equal(AES192, "AES192")
check_equal(AES256, "AES256")
