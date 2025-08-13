from dataParser import *
from dataPlotter import *

import numpy as np

if __name__ == "__main__":

    # Path to your log file
    logA_file_path = "../data/ML-KEM-1024/ML-DSA-87/logA.log"
    logB_file_path = "../data/ML-KEM-1024/ML-DSA-87/logB.log"

    # Read the log file
    logA_lines = read_log_file(logA_file_path)
    logB_lines = read_log_file(logB_file_path)

    # Extract full logs
    full_logsA = extract_logs_by_level(logA_lines, ["INFO", "DEBUG", "ERROR"])
    full_logsB = extract_logs_by_level(logB_lines, ["INFO", "DEBUG", "ERROR"])

    # Check whether PQC or QDK are used for key exchange
    if (log_contains_pattern(full_logsA[0]['message'], "BB84") and
        log_contains_pattern(full_logsB[0]['message'], "BB84")):
        is_QKD = True
    elif (log_contains_pattern(full_logsA[0]['message'], "QKD") and # Necessary condition for older logs that use "QKD"
        log_contains_pattern(full_logsB[0]['message'], "QKD")):
        is_QKD = True
    elif (log_contains_pattern(full_logsA[0]['message'], "ML-KEM") and
        log_contains_pattern(full_logsB[0]['message'], "ML-KEM")):
        is_QKD = False
    else:
        raise KeyboardInterrupt("Terminating due to mismatching TX and RX log files.")

    # Parse known errors in TX
    # - RX errors on TX log
    parsed_logsA, num_errors_A_RX = remove_error_blocks_between_patterns(
        full_logsA,
        "Raw packet received",
        "Encrypted and signed payload forwarded",
        pattern_match_fn=log_contains_pattern,
        inclusive=True,
        error_filter_pattern="HTTP error occurred: 500 Server Error: INTERNAL SERVER ERROR for url: http://192.168.3.102:8080/")
    print(f"Parsed {num_errors_A_RX} errors in TX: Originating from RX")
    # - TX failed to get QKD key (QKD internal error)
    parsed_logsA, num_errors_A_QKD = remove_error_blocks_between_patterns(
        parsed_logsA,
        "Raw packet received",
        "Encrypted and signed payload forwarded",
        pattern_match_fn=log_contains_pattern,
        inclusive=True,
        error_filter_pattern="HTTP error occurred: 500 Server Error: Internal Server Error for url: https://192.168.3.126:8200/")
    print(f"Parsed {num_errors_A_QKD} errors in TX: QKD internal server error")
    # - TX to RX timeout
    parsed_logsA, num_errors_A_timeout = remove_error_blocks_between_patterns(
        parsed_logsA,
        "Raw packet received",
        "Encrypted and signed payload forwarded",
        pattern_match_fn=log_contains_pattern,
        inclusive=True,
        error_filter_pattern="Timeout error occurred: HTTPConnectionPool(host='192.168.3.102', port=8080): Read timed out")
    print(f"Parsed {num_errors_A_timeout} errors in TX: RX timeout")
    # - TX to RX max retries
    parsed_logsA, num_errors_A_retries = remove_error_blocks_between_patterns(
        parsed_logsA,
        "Raw packet received",
        "Encrypted and signed payload forwarded",
        pattern_match_fn=log_contains_pattern,
        inclusive=True,
        error_filter_pattern="Connection error occurred: HTTPConnectionPool(host='192.168.3.102', port=8080): Max retries exceeded")
    print(f"Parsed {num_errors_A_retries} errors in TX: RX max retries exceeded")
    # - Another error...TODO

    # Total number of errors originating from TX
    num_errors_A = num_errors_A_QKD + num_errors_A_timeout + num_errors_A_retries# + ...

    # Parse known errors in RX
    # - RX not finding QKD key on receiver
    parsed_logsB, num_errors_B_QKD = remove_error_blocks_between_patterns(
        full_logsB,
        "Encrypted and signed payload received",
        "172.22.112.1",
        pattern_match_fn=log_contains_pattern,
        inclusive=True,
        error_filter_pattern="HTTP error occurred: 404 Client Error: Not Found for url: https://192.168.3.128:8200/")
    print(f"Parsed {num_errors_B_QKD} errors in RX: QKD key not found")
    # - Another error...TODO

    # Total number of errors originating from RX
    num_errors_B = num_errors_B_QKD # + ...

    # Check for error in the data
    if(contains_error_log(parsed_logsA) or contains_error_log(parsed_logsB)):
        raise KeyboardInterrupt("Terminating test do to unexpected errors: Check log and add unknown errors to parsing.")

    # Collect time deltas between specific logs on TX
    dtimes_tx_A = elapsed_time_between_patterns(
        logs=parsed_logsA,  # list of parsed logs
        start_pattern="Raw packet received",
        end_pattern="Encrypted and signed payload forwarded",
        use_regex=False
    )
    if dtimes_tx_A is None:
        raise KeyboardInterrupt("Terminating: No data to work with in TX")
    if is_QKD:
        dtimes_crypto_A = elapsed_time_between_patterns(
            logs=parsed_logsA,
            start_pattern="Starting new HTTPS connection (1): 192.168.3.126",
            end_pattern="Signed data with private key",
            use_regex=False
        )
        dtimes_QKD_key_A = elapsed_time_between_patterns(
            logs=parsed_logsA,  # list of parsed logs
            start_pattern="Starting new HTTPS connection (1): 192.168.3.126",
            end_pattern="key collected",
            use_regex=False
        )
    else:
        dtimes_crypto_A = elapsed_time_between_patterns(
            logs=parsed_logsA,
            start_pattern="PQC key request initiated",
            end_pattern="Signed data with private key",
            use_regex=False
        )
        dtimes_PQC_key_A = elapsed_time_between_patterns(
            logs=parsed_logsA,  # list of parsed logs
            start_pattern="PQC key request initiated",
            end_pattern="key collected",
            use_regex=False
        )
    dtimes_encrypt_A = elapsed_time_between_patterns(
        logs=parsed_logsA,  # list of parsed logs
        start_pattern="key collected",
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
    if is_QKD:
        dtimes_rx_B = elapsed_time_between_patterns(
            logs=parsed_logsB,  # list of parsed logs
            start_pattern="Encrypted and signed payload received",
            end_pattern="172.22.112.1",
            use_regex=False
        )
    else:
        dtimes_rx_B = elapsed_time_between_patterns(
            logs=parsed_logsB,  # list of parsed logs
            start_pattern="Received KEM request",
            end_pattern="POST /data HTTP/1.1",
            use_regex=False
        )
    if dtimes_rx_B is None:
        raise KeyboardInterrupt("Terminating: No data to work with in RX")
    if is_QKD:
        dtimes_crypto_B = elapsed_time_between_patterns(
            logs=parsed_logsB,
            start_pattern="Encrypted and signed payload received",
            end_pattern="Decrypted data with key",
        )
        dtimes_QKD_key_B = elapsed_time_between_patterns(
            logs=parsed_logsB,  # list of parsed logs
            start_pattern="Starting new HTTPS connection (1): 192.168.3.128",
            end_pattern="key collected",
            use_regex=False
        )
    else:
        dtimes_crypto_B = elapsed_time_between_patterns(
            logs=parsed_logsB,
            start_pattern="Received KEM request",
            end_pattern="Decrypted data with key",
        )
        dtimes_PQC_key_B = elapsed_time_between_patterns(
            logs=parsed_logsB,  # list of parsed logs
            start_pattern="Received KEM request",
            end_pattern="POST /kem HTTP/1.1",
            use_regex=False
        )
        dtimes_idle_B = elapsed_time_between_patterns(
            logs=parsed_logsB,
            start_pattern="POST /kem HTTP/1.1",
            end_pattern="Encrypted and signed payload received",
            use_regex=False
        )
        # Correct for idle time between kem and data requests on RX
        dtimes_rx_B = [a - b for a, b in zip(dtimes_rx_B, dtimes_idle_B)]
        dtimes_crypto_B = [a - b for a, b in zip(dtimes_crypto_B, dtimes_idle_B)]
    dtimes_encrypt_B = elapsed_time_between_patterns(
        logs=parsed_logsB,  # list of parsed logs
        start_pattern="key collected",
        end_pattern="Decrypted data with key",
        use_regex=False
    )
    dtimes_sign_B = elapsed_time_between_patterns(
        logs=parsed_logsB,  # list of parsed logs
        start_pattern="Encrypted and signed payload received",
        end_pattern="Verified signature",
        use_regex=False
    )

    # Collect transmission time of payload
    dtimes_payload = elapsed_time_between_patterns(
        logs=parsed_logsA,
        start_pattern="Starting new HTTP connection (1): 192.168.3.102",
        end_pattern="http://192.168.3.102:8080",
        use_regex=False
    )
    # Correct for kem samples in log block (due to old logs not differentiating kem and data requests very well)
    # Correct for RX processing in payload transmission time
    if is_QKD:
        dtimes_payload = [a - b for a, b in zip(dtimes_payload, dtimes_rx_B)]
    else:
        del dtimes_payload[::2]
        dtimes_payload = [a - b + c for a, b, c in zip(dtimes_payload, dtimes_rx_B, dtimes_PQC_key_B)]

    # Calculated TX metrics
    # - Mean
    avg_time_tx_A = np.mean(dtimes_tx_A)
    if is_QKD:
        avg_time_QKD_key_A = np.mean(dtimes_QKD_key_A)
    else:
        avg_time_PQC_key_A = np.mean(dtimes_PQC_key_A)
    avg_time_encrypt_A = np.mean(dtimes_encrypt_A)
    avg_time_sign_A = np.mean(dtimes_sign_A)
    avg_time_crypto_A = np.mean(dtimes_crypto_A)
    # - Standard deviation
    std_time_tx_A = np.std(dtimes_tx_A)
    if is_QKD:
        std_time_QKD_key_A = np.std(dtimes_QKD_key_A)
    else:
        std_time_PQC_key_A = np.std(dtimes_PQC_key_A)
    std_time_encrypt_A = np.std(dtimes_encrypt_A)
    std_time_sign_A = np.std(dtimes_sign_A)
    std_time_crypto_A = np.std(dtimes_crypto_A)
    # - Max
    max_time_tx_A = np.max(dtimes_tx_A)
    if is_QKD:
        max_time_QKD_key_A = np.max(dtimes_QKD_key_A)
    else:
        max_time_PQC_key_A = np.max(dtimes_PQC_key_A)
    max_time_encrypt_A = np.max(dtimes_encrypt_A)
    max_time_sign_A = np.max(dtimes_sign_A)
    max_time_crypto_A = np.max(dtimes_crypto_A)

    # - Error rates
    err_rate_tx_A = (num_errors_A / (num_errors_A + len(dtimes_tx_A))) * 1000
    err_rate_QKD_key_A = (num_errors_A_QKD / (num_errors_A + len(dtimes_tx_A))) * 1000
    err_rate_PQC_key_A = 0 # Placeholder
    err_rate_encrypt_A = 0 # Placeholder
    err_rate_sign_A = 0 # Placeholder
    err_rate_crypto_A = err_rate_QKD_key_A + err_rate_PQC_key_A + err_rate_encrypt_A + err_rate_sign_A

    # Calculate RX metrics
    # - Mean
    avg_time_rx_B = np.mean(dtimes_rx_B)
    if is_QKD:
        avg_time_QKD_key_B = np.mean(dtimes_QKD_key_B)
    else:
        avg_time_PQC_key_B = np.mean(dtimes_PQC_key_B)
    avg_time_encrypt_B = np.mean(dtimes_encrypt_B)
    avg_time_sign_B = np.mean(dtimes_sign_B)
    avg_time_crypto_B = np.mean(dtimes_crypto_B)
    # - Standard deviation
    std_time_rx_B = np.std(dtimes_rx_B)
    if is_QKD:
        std_time_QKD_key_B = np.std(dtimes_QKD_key_B)
    else:
        std_time_PQC_key_B = np.std(dtimes_PQC_key_B)
    std_time_encrypt_B = np.std(dtimes_encrypt_B)
    std_time_sign_B = np.std(dtimes_sign_B)
    std_time_crypto_B = np.std(dtimes_crypto_B)
    # - Max
    max_time_rx_B = np.max(dtimes_rx_B)
    if is_QKD:
        max_time_QKD_key_B = np.max(dtimes_QKD_key_B)
    else:
        max_time_PQC_key_B = np.max(dtimes_PQC_key_B)
    max_time_encrypt_B = np.max(dtimes_encrypt_B)
    max_time_sign_B = np.max(dtimes_sign_B)
    max_time_crypto_B = np.max(dtimes_crypto_B)
    # - Error rates
    err_rate_rx_B = (num_errors_B / (num_errors_B + len(dtimes_rx_B))) * 1000
    err_rate_QKD_key_B = (num_errors_B_QKD / (num_errors_B + len(dtimes_rx_B))) * 1000
    err_rate_PQC_key_B = 0 # Placeholder
    err_rate_encrypt_B = 0 # Placeholder
    err_rate_sign_B = 0 # Placeholder
    err_rate_crypto_B = err_rate_QKD_key_B + err_rate_encrypt_B + err_rate_sign_B

    # Calculate payload metrics
    # - Mean
    avg_time_payload = np.mean(dtimes_payload)
    # - Standard deviation
    std_time_payload = np.std(dtimes_payload)
    # - Max
    max_time_payload = np.max(dtimes_payload)
    # - Error rates
    err_rate_payload = 0 # Placeholder

    # Print TX metrics
    print("TX average latencies:")
    print("- Full payload processing:")
    print(f"-- Mean: {avg_time_tx_A:.2f} ms")
    print(f"-- Standard deviation: {std_time_tx_A:.2f} ms")
    print(f"-- Max: {max_time_tx_A:.0f} ms")
    print(f"-- Error rate: {err_rate_tx_A:.2f} ‰")
    print("- Payload transmission:")
    print(f"-- Mean: {avg_time_payload:.2f} ms")
    print(f"-- Standard deviation: {std_time_payload:.2f} ms")
    print(f"-- Max: {max_time_payload:.0f} ms")
    print(f"-- Error rate: {err_rate_payload:.2f} ‰")
    print("- Crypto processing:")
    print(f"-- Mean: {avg_time_crypto_A:.2f} ms")
    print(f"-- Standard deviation: {std_time_crypto_A:.2f} ms")
    print(f"-- Max: {max_time_crypto_A:.0f} ms")
    print(f"-- Error rate: {err_rate_crypto_A:.2f} ‰")
    if is_QKD:
        print("- QKD key collection:")
        print(f"-- Mean: {avg_time_QKD_key_A:.2f} ms")
        print(f"-- Standard deviation: {std_time_QKD_key_A:.2f} ms")
        print(f"-- Max: {max_time_QKD_key_A:.0f} ms")
        print(f"-- Error rate: {err_rate_QKD_key_A:.2f} ‰")
    else:
        print("- PQC key collection:")
        print(f"-- Mean: {avg_time_PQC_key_A:.2f} ms")
        print(f"-- Standard deviation: {std_time_PQC_key_A:.2f} ms")
        print(f"-- Max: {max_time_PQC_key_A:.0f} ms")
        print(f"-- Error rate: {err_rate_PQC_key_A:.2f} ‰")
    print("- Encryption:")
    print(f"-- Mean: {avg_time_encrypt_A:.2f} ms")
    print(f"-- Standard deviation: {std_time_encrypt_A:.2f} ms")
    print(f"-- Max: {max_time_encrypt_A:.0f} ms")
    print(f"-- Error rate: {err_rate_encrypt_A:.2f} ‰")
    print("- Signature:")
    print(f"-- Mean: {avg_time_sign_A:.2f} ms")
    print(f"-- Standard deviation: {std_time_sign_A:.2f} ms")
    print(f"-- Max: {max_time_sign_A:.0f} ms")
    print(f"-- Error rate: {err_rate_sign_A:.2f} ‰")

    # Print RX metrics
    print("RX average latencies:")
    print("- Full payload processing:")
    print(f"-- Mean: {avg_time_rx_B:.2f} ms")
    print(f"-- Standard deviation: {std_time_rx_B:.2f} ms")
    print(f"-- Max: {max_time_rx_B:.0f} ms")
    print(f"-- Error rate: {err_rate_rx_B:.2f} ‰")
    print("- Crypto processing:")
    print(f"-- Mean: {avg_time_crypto_B:.2f} ms")
    print(f"-- Standard deviation: {std_time_crypto_B:.2f} ms")
    print(f"-- Max: {max_time_crypto_B:.0f} ms")
    print(f"-- Error rate: {err_rate_crypto_B:.2f} ‰")
    if is_QKD:
        print("- QKD key collection:")
        print(f"-- Mean: {avg_time_QKD_key_B:.2f} ms")
        print(f"-- Standard deviation: {std_time_QKD_key_B:.2f} ms")
        print(f"-- Max: {max_time_QKD_key_B:.0f} ms")
        print(f"-- Error rate: {err_rate_QKD_key_B:.2f} ‰")
    else:
        print("- PQC key collection:")
        print(f"-- Mean: {avg_time_PQC_key_B:.2f} ms")
        print(f"-- Standard deviation: {std_time_PQC_key_B:.2f} ms")
        print(f"-- Max: {max_time_PQC_key_B:.0f} ms")
        print(f"-- Error rate: {err_rate_PQC_key_B:.2f} ‰")
    print("- Encryption:")
    print(f"-- Mean: {avg_time_encrypt_B:.2f} ms")
    print(f"-- Standard deviation: {std_time_encrypt_B:.2f} ms")
    print(f"-- Max: {max_time_encrypt_B:.0f} ms")
    print(f"-- Error rate: {err_rate_encrypt_B:.2f} ‰")
    print("- Signature:")
    print(f"-- Mean: {avg_time_sign_B:.2f} ms")
    print(f"-- Standard deviation: {std_time_sign_B:.2f} ms")
    print(f"-- Max: {max_time_sign_B:.0f} ms")
    print(f"-- Error rate: {err_rate_sign_B:.2f} ‰")

    # Plot a histogram for the time deltas of TX
    plot_time_deltas_bar(
        dtimes_tx_A,
        bin_size=10,
        title="TX payload processing latency",
        xlim_max=300,
        show_overflow_bins=True,
        output_pdf_path="TX_payload_processing_latency.pdf")
    plot_time_deltas_bar(
        dtimes_crypto_A,
        bin_size=10,
        title="TX cryptography processing latency",
        xlim_max=300,
        show_overflow_bins=True,
        output_pdf_path="TX_crypto_processing_latency.pdf")
    if is_QKD:
        plot_time_deltas_bar(
            dtimes_QKD_key_A,
            bin_size=10,
            title="TX key exchange latency",
            xlim_max=300,
            show_overflow_bins=True,
            output_pdf_path="TX_key_exchange_latency.pdf")
    else:
        plot_time_deltas_bar(
            dtimes_PQC_key_A,
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

    # Plot a histogram for the time deltas of RX
    plot_time_deltas_bar(
        dtimes_rx_B,
        bin_size=10,
        title="RX payload processing latency",
        xlim_max=300,
        show_overflow_bins=True,
        output_pdf_path="RX_payload_processing_latency.pdf")
    plot_time_deltas_bar(
        dtimes_crypto_B,
        bin_size=10,
        title="RX cryptography processing latency",
        xlim_max=300,
        show_overflow_bins=True,
        output_pdf_path="RX_crypto_latency.pdf"
    )
    if is_QKD:
        plot_time_deltas_bar(
            dtimes_QKD_key_B,
            bin_size=10,
            title="RX key exchange latency",
            xlim_max=300,
            show_overflow_bins=True,
            output_pdf_path="RX_key_exchange_latency.pdf")
    else:
        plot_time_deltas_bar(
            dtimes_PQC_key_B,
            bin_size=10,
            title="RX key exchange latency",
            xlim_max=300,
            show_overflow_bins=True,
            output_pdf_path="RX_key_exchange_latency.pdf")
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

    plot_time_deltas_bar(
        dtimes_payload,
        bin_size=10,
        title="Payload transmission latency",
        xlim_max=300,
        show_overflow_bins=True,
        output_pdf_path="payload_transmission_latency.pdf"
    )

