import matplotlib.pyplot as plt
from collections import Counter
from typing import List, Optional
import numpy as np


def plot_time_deltas_bar(
    deltas: List[float],
    bin_size: int = 10,
    title: str = "Time Delta Distribution",
    xlim_min: Optional[float] = None,
    xlim_max: Optional[float] = None,
    show_overflow_bins: bool = True,
    output_pdf_path: Optional[str] = None
):
    """
    Plot a bar chart of time deltas with optional overflow bins,
    a mean line, and export to PDF if a path is provided.

    Args:
        deltas (List[float]): Time deltas in milliseconds.
        bin_size (int): Width of bins in ms.
        title (str): Plot title.
        xlim_min (Optional[float]): Min value to include.
        xlim_max (Optional[float]): Max value to include.
        show_overflow_bins (bool): Whether to show overflow bins.
        output_pdf_path (Optional[str]): Path to save PDF (e.g., 'output.pdf').
    """
    if not deltas:
        print("No data to plot.")
        return

    mean_val = np.mean(deltas)
    max_val = max(deltas)

    underflow = [d for d in deltas if xlim_min is not None and d < xlim_min]
    overflow = [d for d in deltas if xlim_max is not None and d > xlim_max]
    filtered = [d for d in deltas if (xlim_min is None or d >= xlim_min) and (xlim_max is None or d <= xlim_max)]

    if not filtered and not (show_overflow_bins and (underflow or overflow)):
        print("No data to plot.")
        return

    binned = [int(d // bin_size) * bin_size for d in filtered]
    counts = Counter(binned)

    if binned:
        min_bin = int(min(binned) // bin_size) * bin_size
        max_bin = int(max(binned) // bin_size) * bin_size
        full_bins = range(min_bin, max_bin + bin_size, bin_size)
    else:
        full_bins = []

    x_labels = []
    y_counts = []
    colors = []
    x_positions = []

    if show_overflow_bins and underflow:
        x_labels.append(f"< {xlim_min:.0f} ms")
        y_counts.append(len(underflow))
        colors.append("darkblue")
        x_positions.append(-1)

    for b in full_bins:
        x_labels.append(f"{b}-{b + bin_size - 1} ms")
        y_counts.append(counts.get(b, 0))
        colors.append("skyblue")
        x_positions.append(b + bin_size / 2)

    overflow_x = None
    if show_overflow_bins and overflow:
        x_labels.append(f"> {xlim_max:.0f} ms")
        y_counts.append(len(overflow))
        colors.append("blue")
        overflow_x = x_positions[-1] + bin_size if x_positions else 0
        x_positions.append(overflow_x)

    plt.figure(figsize=(6, 6))
    plt.bar(x_positions, y_counts, color=colors, edgecolor='black', width=bin_size * 0.9)
    plt.xticks(x_positions, x_labels, rotation=45, ha='right', fontsize=10)
    # plt.xlabel("Time Delta Bins (ms)")
    plt.ylabel("Count", fontsize=10)
    # plt.title(title)
    plt.grid(axis='y', linestyle='--', alpha=0.5)

    plt.axvline(x=mean_val, color='red', linestyle='--', linewidth=1.5)
    plt.text(
        mean_val,
        max(y_counts) * 0.95,
        f" Mean: {mean_val:.0f} ms",
        color='red',
        fontsize=10,
        ha='left',
        va='top',
        fontweight='bold',
        # rotation=90,
        # backgroundcolor='white'
    )

    if overflow and show_overflow_bins and overflow_x is not None:
        plt.text(
            overflow_x,
            y_counts[-1] + max(y_counts) * 0.02,
            f"Max:\n{max_val:.0f} ms",
            ha='center',
            va='bottom',
            fontsize=10,
            color='blue',
            fontweight='bold'
        )

    plt.tight_layout()

    if output_pdf_path:
        plt.savefig(output_pdf_path, format='pdf')
        print(f"Plot saved to PDF: {output_pdf_path}")

    plt.show()


def plot_time_deltas_ccdf(
    latencies: List[float],
    title: str = "Latency CCDF",
    xlabel: str = "Latency (ms)",
    ylabel: str = "CCDF",
    save_path: Optional[str] = None,
    percentiles: Optional[List[int]] = None,
    log_y: bool = False,
    show_max: bool = True,
    x_offset_fraction: float = 5*10**-3,   # fraction of x-axis range for label offset
    y_offset_fraction: float = 8*10**-6    # fraction of y-axis range for label offset
):
    """
    Plots the Complementary Cumulative Distribution Function (CCDF)
    of an array of latencies in milliseconds.

    Args:
        latencies (List[float]): A list of latency values in milliseconds.
        title (str): Title of the plot.
        xlabel (str): Label for the x-axis.
        ylabel (str): Label for the y-axis.
        save_path (Optional[str]): If provided, saves the figure as a PDF to this path.
        percentiles (Optional[List[int]]): List of percentiles to mark on the CCDF (e.g., [50, 90, 99]).
        log_y (bool): If True, the Y-axis is logarithmic (final CCDF=0 replaced by 1/N).
        show_max (bool): If True, annotate the maximum latency value on the plot.
        x_offset_fraction (float): Fraction of x-axis span to shift labels horizontally.
        y_offset_fraction (float): Fraction of y-axis span to shift labels vertically.
    """
    if not latencies:
        print("No data to plot.")
        return

    # Sort latencies
    data = np.sort(latencies)
    N = len(data)

    # Compute cumulative probabilities
    cdf = np.arange(1, N + 1) / N
    ccdf = 1 - cdf

    # Fix log-scale issue: replace final 0 with 1/N
    if log_y:
        ccdf[-1] = 1.0 / N

    # Plot CCDF as black line with blue sample points
    plt.figure(figsize=(7, 4))
    plt.plot(data, ccdf, linestyle='-', color='black')   # line
    plt.scatter(data, ccdf, color='blue', s=15, rasterized=True)          # points

    # Fix Y-axis before annotations
    if log_y:
        plt.yscale("log")
        plt.ylim(1.0 / (N * 2), 1)   # slightly below lowest point
    else:
        plt.ylim(0, 1)

    # Get axis ranges for scaling
    xmin, xmax = plt.xlim()
    ymin, ymax = plt.ylim()

    # Compute scaled offsets
    x_offset = (xmax - xmin) * x_offset_fraction
    y_offset = (ymax - ymin) * y_offset_fraction

    # Add percentile markers if provided
    if percentiles:
        for p in percentiles:
            if 0 <= p <= 100:
                value = np.percentile(data, p)
                plt.axvline(value, color='red', linestyle='--', alpha=0.7)
                plt.text(value + x_offset, ymin + y_offset,
                         f"p{p} = {value:.2f} ms",
                         # f"p{p} = {value:.0f} bytes",
                         rotation=90, verticalalignment='bottom',
                         color='red', fontweight='bold', fontsize=12)

    # Annotate maximum latency
    if show_max:
        max_val = np.max(data)
        plt.axvline(max_val, color='red', linestyle='--', alpha=0.7)
        plt.text(max_val + x_offset, ymin + y_offset,
                 f"max = {max_val:.2f} ms",
                 # f"max = {max_val:.0f} bytes",
                 rotation=90, verticalalignment='bottom',
                 color='red', fontweight='bold', fontsize=12)

    # Labels and styling
    plt.xlabel(xlabel, fontsize=12)
    plt.ylabel(ylabel, fontsize=12)
    plt.xticks(fontsize=12)
    plt.yticks(fontsize=12)
    # plt.title(title, fontsize=13)
    plt.grid(True, linestyle='--', alpha=0.6)

    plt.tight_layout()

    # Save or show
    if save_path:
        plt.savefig(save_path, format="pdf")
        print(f"CCDF plot saved to {save_path}")

    plt.show()


def plot_time_deltas_ccdf_multi(
    datasets: List[List[float]],
    labels: Optional[List[str]] = None,
    labels_short: Optional[List[str]] = None,
    # title: str = "Latency CCDF Comparison",
    xlabel: str = "Latency (ms)",
    ylabel: str = "CCDF",
    save_path: Optional[str] = None,
    percentiles: Optional[List[int]] = None,
    log_y: bool = False,
    show_max: bool = True,
    x_offset_fraction: float = 5*10**-3,  # fraction of x-axis range for label offset
    y_offset_fraction: float = 1*10**-6,  # fraction of y-axis range for label offset
    rasterize_points: bool = True,
    colors: Optional[List[str]] = None,
):
    """
    Plots the Complementary Cumulative Distribution Function (CCDF)
    for multiple datasets of latencies in milliseconds.

    Args:
        datasets (List[List[float]]): List of latency datasets (each a list of floats).
        labels (Optional[List[str]]): Labels for datasets (defaults to Dataset 1, Dataset 2, ...).
        title (str): Plot title.
        xlabel (str): Label for x-axis.
        ylabel (str): Label for y-axis.
        save_path (Optional[str]): If provided, saves figure as PDF.
        percentiles (Optional[List[int]]): Percentiles to mark for each dataset.
        log_y (bool): If True, Y-axis is logarithmic.
        show_max (bool): If True, annotate maximum value per dataset.
        x_offset_fraction (float): Horizontal offset fraction for annotation text.
        y_offset_fraction (float): Vertical offset fraction for annotation text.
        rasterize_points (bool): Rasterize scatter points for lighter PDFs.
        colors (Optional[List[str]]): Custom colors for datasets.
    """

    def compute_ccdf(data, log_y):
        """Helper to compute CCDF values for a sorted dataset."""
        N = len(data)
        cdf = np.arange(1, N + 1) / N
        ccdf = 1 - cdf
        if log_y:
            ccdf[-1] = 1.0 / N  # replace final zero
        return ccdf

    if not datasets or all(len(d) == 0 for d in datasets):
        print("No data provided for plotting.")
        return

    num_sets = len(datasets)
    if not labels:
        labels = [f"Dataset {i+1}" for i in range(num_sets)]
    if not labels_short:
        labels_short = labels

    if not colors:
        # Default color cycle (black line + colored points)
        base_colors = ["blue", "green", "red", "purple", "orange", "brown", "pink", "gray"]
        colors = base_colors[:num_sets]

    plt.figure(figsize=(7, 4))

    # Track axis limits for annotations
    ymin, ymax = (None, None)
    xmin, xmax = (None, None)

    for i, (data, label, color) in enumerate(zip(datasets, labels, colors)):
        if not data:
            continue

        # Sort & compute CCDF
        data_sorted = np.sort(data)
        ccdf = compute_ccdf(data_sorted, log_y)

        # Plot line + scatter
        plt.plot(data_sorted, ccdf, linestyle='-', color='black', linewidth=0.8)
        plt.scatter(data_sorted, ccdf, color=color, s=12, rasterized=rasterize_points, label=label)

        # Update axis ranges
        if xmin is None:
            xmin, xmax = np.min(data_sorted), np.max(data_sorted)
            ymin, ymax = np.min(ccdf), np.max(ccdf)
        else:
            xmin, xmax = min(xmin, np.min(data_sorted)), max(xmax, np.max(data_sorted))
            ymin, ymax = min(ymin, np.min(ccdf)), max(ymax, np.max(ccdf))

    # Apply log scale if requested
    if log_y:
        ymin = min(1.0 / (max(len(d) for d in datasets) * 10), ymin)
        plt.yscale("log")
        plt.ylim(ymin, 1)
    else:
        plt.ylim(0, 1)

    # Axis ranges for annotation offsets
    xmin, xmax = plt.xlim()
    ymin, ymax = plt.ylim()
    x_offset = (xmax - xmin) * x_offset_fraction
    y_offset = (ymax - ymin) * y_offset_fraction

    # Percentile annotations
    if percentiles:
        for data, label, color in zip(datasets, labels_short, colors):
            if not data:
                continue
            for p in percentiles:
                if 0 <= p <= 100:
                    value = np.percentile(data, p)
                    plt.axvline(value, color=color, linestyle='--', alpha=0.6)
                    plt.text(value + x_offset, ymin + y_offset,
                             # f"{label} p{p} = {value:.2f} ms",
                             f"p{p} = {value:.2f} ms",
                             rotation=90, verticalalignment='bottom',
                             color=color, fontweight='bold', fontsize=12)

    # Max annotations
    if show_max:
        for data, label, color in zip(datasets, labels_short, colors):
            if not data:
                continue
            max_val = np.max(data)
            plt.axvline(max_val, color=color, linestyle='--', alpha=0.7)
            plt.text(max_val + x_offset, ymin + y_offset,
                     # f"{label} max = {max_val:.2f} ms",
                     f"max = {max_val:.2f} ms",
                     rotation=90, verticalalignment='bottom',
                     color=color, fontweight='bold', fontsize=12)

    # Labels & layout
    plt.xlabel(xlabel, fontsize=12)
    plt.ylabel(ylabel, fontsize=12)
    plt.xticks(fontsize=12)
    plt.yticks(fontsize=12)
    # plt.title(title, fontsize=13)
    plt.grid(True, linestyle='--', alpha=0.6)
    plt.legend(fontsize=12)
    plt.tight_layout()

    if save_path:
        plt.savefig(save_path, format="pdf")
        print(f"Multi-dataset CCDF plot saved to {save_path}")
    plt.show()