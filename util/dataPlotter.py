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

    plt.figure(figsize=(12, 6))
    plt.bar(x_positions, y_counts, color=colors, edgecolor='black', width=bin_size * 0.9)
    plt.xticks(x_positions, x_labels, rotation=45, ha='right')
    # plt.xlabel("Time Delta Bins (ms)")
    plt.ylabel("Count")
    plt.title(title)
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
        # rotation=90,
        # backgroundcolor='white'
    )

    if overflow and show_overflow_bins and overflow_x is not None:
        plt.text(
            overflow_x,
            y_counts[-1] + max(y_counts) * 0.02,
            f"Max: {max_val:.0f} ms",
            ha='center',
            va='bottom',
            fontsize=9,
            color='blue',
            fontweight='bold'
        )

    plt.tight_layout()

    if output_pdf_path:
        plt.savefig(output_pdf_path, format='pdf')
        print(f"Plot saved to PDF: {output_pdf_path}")

    plt.show()

