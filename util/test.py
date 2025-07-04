from dataParser import *
from dataPlotter import *


if __name__ == "__main__":
    # Path to your log file
    logA_file_path = "../data/20km/ML-DSA-87/logA.log"
    logB_file_path = "../data/20km/ML-DSA-87/logB.log"

    # Read the log file
    logA_lines = read_log_file(logA_file_path)
    logB_lines = read_log_file(logB_file_path)

    # Extract full logs
    full_logsA = extract_logs_by_level(logA_lines, ["INFO", "DEBUG", "ERROR"])
    full_logsB = extract_logs_by_level(logB_lines, ["INFO", "DEBUG", "ERROR"])

    # Parse known errors
    parsed_logsA, num_errors_A = remove_error_blocks_between_patterns(
        full_logsA,
        "Raw packet received",
        "Encrypted and signed payload forwarded",
        pattern_match_fn=log_contains_pattern,
        inclusive=True,
        error_filter_pattern="HTTP error occurred: 500 Server Error: INTERNAL SERVER ERROR for url: http://192.168.3.102:8080/")
    print(f"Parsed {num_errors_A} errors in TX")
    parsed_logsB, num_errors_B = remove_error_blocks_between_patterns(
        full_logsB,
        "Encrypted and signed payload received",
        "Raw packet forwarded",
        pattern_match_fn=log_contains_pattern,
        inclusive=True,
        error_filter_pattern="HTTP error occurred: 404 Client Error: Not Found for url: https://192.168.3.128:8200/")
    print(f"Parsed {num_errors_B} errors in RX")

    # Check for error in the data
    if(contains_error_log(parsed_logsA) or contains_error_log(parsed_logsB)):
        raise KeyboardInterrupt(f"Terminating test do to unexpected errors")

    # Collect time deltas between specific logs on TX
    dtimes_tx_A = elapsed_time_between_patterns(
        logs=parsed_logsA,  # list of parsed logs
        start_pattern="Raw packet received",
        end_pattern="Encrypted and signed payload forwarded",
        use_regex=False
    )
    dtimes_QKD_key_A = elapsed_time_between_patterns(
        logs=parsed_logsA,  # list of parsed logs
        start_pattern="Starting new HTTPS connection (1): 192.168.3.126",
        end_pattern="QKD key collected",
        use_regex=False
    )
    dtimes_encrypt_A = elapsed_time_between_patterns(
        logs=parsed_logsA,  # list of parsed logs
        start_pattern="QKD key collected",
        end_pattern="Encrypted data with key",
        use_regex=False
    )
    dtimes_sign_A = elapsed_time_between_patterns(
        logs=parsed_logsA,  # list of parsed logs
        start_pattern="Encrypted data with key",
        end_pattern="Signed data with private key",
        use_regex=False
    )

    # Collect time deltas between specific logs on RX
    dtimes_rx_B = elapsed_time_between_patterns(
        logs=parsed_logsB,  # list of parsed logs
        start_pattern="Encrypted and signed payload received",
        end_pattern="Raw packet forwarded",
        use_regex=False
    )
    dtimes_QKD_key_B = elapsed_time_between_patterns(
        logs=parsed_logsB,  # list of parsed logs
        start_pattern="Starting new HTTPS connection (1): 192.168.3.128",
        end_pattern="QKD key collected",
        use_regex=False
    )
    dtimes_encrypt_B = elapsed_time_between_patterns(
        logs=parsed_logsB,  # list of parsed logs
        start_pattern="QKD key collected",
        end_pattern="Decrypted data with key",
        use_regex=False
    )
    dtimes_sign_B = elapsed_time_between_patterns(
        logs=parsed_logsB,  # list of parsed logs
        start_pattern="Encrypted and signed payload received",
        end_pattern="Verified signature",
        use_regex=False
    )

    # Calculated TX metrics
    avg_time_tx_A = sum(dtimes_tx_A) / len(dtimes_tx_A)
    avg_time_QKD_key_A = sum(dtimes_QKD_key_A) / len(dtimes_QKD_key_A)
    avg_time_encrypt_A = sum(dtimes_encrypt_A) / len(dtimes_encrypt_A)
    avg_time_sign_A = sum(dtimes_sign_A) / len(dtimes_sign_A)

    # Calculate RX metrics
    avg_time_rx_B = sum(dtimes_rx_B) / len(dtimes_rx_B)
    avg_time_QKD_key_B = sum(dtimes_QKD_key_B) / len(dtimes_QKD_key_B)
    avg_time_encrypt_B = sum(dtimes_encrypt_B) / len(dtimes_encrypt_B)
    avg_time_sign_B = sum(dtimes_sign_B) / len(dtimes_sign_B)

    # Print TX metrics
    print("TX average latencies:")
    if avg_time_tx_A is not None:
        print(f"- Full payload processing: {avg_time_tx_A:.2f} ms")
    else:
        print("- Full payload processing: No valid start-end pairs found.")
    if avg_time_QKD_key_A is not None:
        print(f"- QKD key collection: {avg_time_QKD_key_A:.2f} ms")
    else:
        print("- QKD key collection: No valid start-end pairs found.")
    if avg_time_encrypt_A is not None:
        print(f"- Encryption: {avg_time_encrypt_A:.2f} ms")
    else:
        print("- Encryption: No valid start-end pairs found.")
    if avg_time_sign_A is not None:
        print(f"- Signature: {avg_time_sign_A:.2f} ms")
    else:
        print("- Signature: No valid start-end pairs found.")

    # Print RX metrics
    print("RX average latencies:")
    if avg_time_rx_B is not None:
        print(f"- Full payload processing: {avg_time_rx_B:.2f} ms")
    else:
        print("- Full payload processing: No valid start-end pairs found.")
    if avg_time_QKD_key_B is not None:
        print(f"- QKD key collection: {avg_time_QKD_key_B:.2f} ms")
    else:
        print("- QKD key collection: No valid start-end pairs found.")
    if avg_time_encrypt_B is not None:
        print(f"- Encryption: {avg_time_encrypt_B:.2f} ms")
    else:
        print("- Encryption: No valid start-end pairs found.")
    if avg_time_sign_B is not None:
        print(f"- Signature: {avg_time_sign_B:.2f} ms")
    else:
        print("- Signature: No valid start-end pairs found.")

    # Plot a histogram for the time deltas
    plot_time_deltas_bar(
        dtimes_tx_A,
        bin_size=10,
        title="TX payload processing latency",
        xlim_max=300,
        show_overflow_bins=True,
        output_pdf_path="TX_payload_processing_latency.pdf")
    plot_time_deltas_bar(
        dtimes_QKD_key_A,
        bin_size=10,
        title="TX key exchange latency",
        xlim_max=300,
        show_overflow_bins=True,
        output_pdf_path="TX_key_exchange_latency.pdf")
    plot_time_deltas_bar(
        dtimes_encrypt_A,
        bin_size=10,
        title="TX encryption latency",
        xlim_max=300,
        show_overflow_bins=True,
        output_pdf_path="TX_encryption_latency.pdf")
    plot_time_deltas_bar(
        dtimes_sign_A,
        bin_size=10,
        title="TX digital signature latency",
        xlim_max=300,
        show_overflow_bins=True,
        output_pdf_path="TX_signature_latency.pdf")

    plot_time_deltas_bar(
        dtimes_rx_B,
        bin_size=10,
        title="RX payload processing latency",
        xlim_max=300,
        show_overflow_bins=True,
        output_pdf_path="RX_payload_processing_latency.pdf")
    plot_time_deltas_bar(
        dtimes_QKD_key_B,
        bin_size=10,
        title="RX key exchange latency",
        xlim_max=300,
        show_overflow_bins=True,
        output_pdf_path="RX_key exchange_latency.pdf")
    plot_time_deltas_bar(
        dtimes_encrypt_B,
        bin_size=10,
        title="RX decryption latency",
        xlim_max=300,
        show_overflow_bins=True,
        output_pdf_path="RX_encryption_latency.pdf")
    plot_time_deltas_bar(
        dtimes_sign_B,
        bin_size=10,
        title="RX digital signature verification latency",
        xlim_max=300,
        show_overflow_bins=True,
        output_pdf_path="RX_signature_latency.pdf")

