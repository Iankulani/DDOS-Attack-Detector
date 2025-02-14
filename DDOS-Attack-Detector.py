# -*- coding: utf-8 -*-
"""
Created on Tue Feb 4 08:27:25 2025

@author: IAN CARTER KULANI

"""

import matplotlib.pyplot as plt
import pandas as pd
import random
import time

# Function to simulate request logs (for the sake of demo)
def generate_request_data(ip_address, duration_seconds=60, frequency=1):
    """
    Simulates request logs for a specific IP over a given time period (e.g., 60 seconds).
    Args:
    - ip_address: IP to simulate requests for.
    - duration_seconds: Duration of the simulation in seconds.
    - frequency: Frequency of requests per second.
    
    Returns a list of timestamps and IP addresses that mimic request logs.
    """
    request_data = []
    
    # Simulating requests
    for second in range(duration_seconds):
        # Each second, add requests based on a random frequency
        num_requests = random.randint(0, frequency)  # Random number of requests
        for _ in range(num_requests):
            request_data.append((ip_address, time.time() + second))
    
    return request_data

# Function to detect DDoS attack based on frequency of requests
def detect_ddos(requests, threshold=10):
    """
    Detect if there is a DDoS attack by checking if an IP exceeds a threshold number of requests per second.
    Args:
    - requests: List of (ip, timestamp) tuples representing request logs.
    - threshold: Maximum number of requests per second to consider normal.
    
    Returns a flag indicating if DDoS was detected.
    """
    # Convert request data into a DataFrame to analyze the data
    df = pd.DataFrame(requests, columns=['IP', 'Timestamp'])
    
    # Group by IP and count requests per second
    df['Minute'] = df['Timestamp'].apply(lambda x: int(x // 60))  # Group by minute
    request_counts = df.groupby(['IP', 'Minute']).size().reset_index(name='Requests')
    
    # Check if any IP exceeds the threshold
    suspicious_ips = request_counts[request_counts['Requests'] > threshold]
    
    if not suspicious_ips.empty:
        print("Possible DDoS attack detected!")
        print(suspicious_ips)
        return True
    else:
        print("No DDoS attack detected.")
        return False

# Function to plot the curve chart (request frequency over time)
def plot_request_frequency(requests):
    """
    Plots the request frequency per second.
    Args:
    - requests: List of (ip, timestamp) tuples representing request logs.
    """
    # Convert request data into DataFrame for easy processing
    df = pd.DataFrame(requests, columns=['IP', 'Timestamp'])
    
    # Group by second and count requests
    df['Second'] = df['Timestamp'].apply(lambda x: int(x % 60))  # Group by second (within the minute)
    request_counts = df.groupby(['Second']).size().reset_index(name='Requests')
    
    # Plotting the data
    plt.plot(request_counts['Second'], request_counts['Requests'], marker='o', color='b', linestyle='-', label="Request Frequency")
    plt.title("IP Request Frequency Over Time")
    plt.xlabel("Time (Seconds)")
    plt.ylabel("Request Count")
    plt.grid(True)
    plt.legend()
    plt.show()

# Main flow of the program
if __name__ == "__main__":
    ip_address = input("Enter the IP address to check for DDoS attack:")
    
    # Simulate a request log for the IP address over 60 seconds
    request_logs = generate_request_data(ip_address, duration_seconds=60, frequency=5)
    
    # Detect DDoS attack based on the simulated requests
    is_ddos = detect_ddos(request_logs, threshold=10)
    
    # Plot request frequency over time
    plot_request_frequency(request_logs)
