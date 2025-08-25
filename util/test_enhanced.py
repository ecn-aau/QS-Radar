from dataParser import *
from dataPlotter import *

import numpy as np

if __name__ == "__main__":

    num_samples = 10**5 # TODO: I can make this dynamic

    # Path to your log file
    logA_file_path = "../data/hybrid/ML-DSA-87/logA.log"
    logB_file_path = "../data/hybrid/ML-DSA-87/logB.log"

    # Read the log file
    logA_lines = read_log_file(logA_file_path)
    logB_lines = read_log_file(logB_file_path)

    # Extract full logs
    full_logsA = extract_logs_by_level(logA_lines, ["INFO", "DEBUG", "WARNING", "ERROR"])
    full_logsB = extract_logs_by_level(logB_lines, ["INFO", "DEBUG", "WARNING", "ERROR"])

    # Count known non-critical errors in TX
    # - RX errors on TX log
    test_logsA, num_errors_A_RX = remove_error_blocks_between_patterns(
        full_logsA,
        "Raw packet received",
        "Encrypted and signed payload forwarded",
        pattern_match_fn=log_contains_pattern,
        inclusive=True,
        error_filter_pattern="HTTP error occurred: 500 Server Error: INTERNAL SERVER ERROR for url: http://192.168.3.102:8080/")
    print(f"Parsed {num_errors_A_RX} errors in TX: Originating from RX")
    # - TX failed to get QKD key (timeout)
    test_logsA, num_errors_A_QKDtimeout = remove_error_blocks_between_patterns(
        test_logsA,
        "Raw packet received",
        "Encrypted and signed payload forwarded",
        pattern_match_fn=log_contains_pattern,
        inclusive=True,
        error_filter_pattern="""Timeout error occurred: HTTPSConnectionPool(host='192.168.3.126', port=8200): Read timed out""")
    print(f"Parsed {num_errors_A_QKDtimeout} errors in TX: QKD timeout")
    # - TX failed to get QKD key (max retries)
    test_logsA, num_errors_A_QKDretries = remove_error_blocks_between_patterns(
        test_logsA,
        "Raw packet received",
        "Encrypted and signed payload forwarded",
        pattern_match_fn=log_contains_pattern,
        inclusive=True,
        error_filter_pattern="""Connection error occurred: HTTPSConnectionPool(host='192.168.3.126', port=8200): Max retries""")
    print(f"Parsed {num_errors_A_QKDretries} errors in TX: QKD max retries")
    # - RX failed to acknowledge data (timeout)
    test_logsA, num_errors_A_timeout = remove_error_blocks_between_patterns(
        test_logsA,
        "Raw packet received",
        "Encrypted and signed payload forwarded",
        pattern_match_fn=log_contains_pattern,
        inclusive=True,
        error_filter_pattern="""Timeout error occurred: HTTPConnectionPool(host='192.168.3.102', port=8080): Read timed out""")
    print(f"Parsed {num_errors_A_timeout} errors in TX: RX timeout")
    # - RX failed to acknowledge data (max retries)
    test_logsA, num_errors_A_retries = remove_error_blocks_between_patterns(
        test_logsA,
        "Raw packet received",
        "Encrypted and signed payload forwarded",
        pattern_match_fn=log_contains_pattern,
        inclusive=True,
        error_filter_pattern="""Connection error occurred: HTTPConnectionPool(host='192.168.3.102', port=8080): Max retries""")
    print(f"Parsed {num_errors_A_retries} errors in TX: RX max retries")
    # - Another error...TODO

    # Parse and count known critical errors in TX
    # - RX failed to answer PQC request (max retries)
    parsed_logsA, num_errors_A_PQC = remove_error_blocks_between_patterns(
        full_logsA,
        "Raw packet received",
        "Encrypted and signed payload forwarded",
        pattern_match_fn=log_contains_pattern,
        inclusive=True,
        error_filter_pattern="""HTTPConnectionPool(host='192.168.3.102', port=8080): Max retries exceeded with url: /kem""")
    print(f"Parsed {num_errors_A_PQC} errors in TX: PQC max retries")
    # - Another error...TODO

    # Total number of errors originating from TX
    num_errors_A_QKD = num_errors_A_QKDtimeout + num_errors_A_QKDretries
    num_errors_A_data = num_errors_A_retries + num_errors_A_timeout
    num_errors_A = num_errors_A_QKD + num_errors_A_data# + ...
    num_errors_A_fatal = num_errors_A_PQC# + ...
    num_errors_A_total = num_errors_A + num_errors_A_fatal

    # Parse and count known errors in RX
    # - RX failed to get QKD key
    parsed_logsB, num_errors_B_QKD = remove_error_blocks_between_patterns(
        full_logsB,
        "Encrypted and signed payload received",
        "172.22.112.1",
        pattern_match_fn=log_contains_pattern,
        inclusive=True,
        error_filter_pattern="QKD key request failed")
    print(f"Parsed {num_errors_B_QKD} errors in RX: QKD error")
    # - Another error...TODO

    # Total number of errors originating from RX
    num_errors_B = num_errors_B_QKD # + ...
    num_errors_B_fatal = 0 # Placeholder

    # Check for error in the data
    if(contains_error_log(test_logsA)):# or contains_error_log(parsed_logsB)):
        raise KeyboardInterrupt("Terminating test do to unexpected errors: Check log and add unknown errors to parsing.")

    # Collect time deltas between specific logs on TX
    dtimes_tx_A = elapsed_time_between_patterns(
        logs=parsed_logsA,  # list of parsed logs
        start_pattern="Raw packet received",
        end_pattern="Encrypted and signed payload forwarded"
    )
    if dtimes_tx_A is None:
        raise KeyboardInterrupt("Terminating: No data to work with in TX")
    dtimes_crypto_A = (elapsed_time_between_patterns(
        logs=parsed_logsA,
        start_pattern="Starting new HTTPS connection (1): 192.168.3.126",
        end_pattern="Signed data with private key") +
                       elapsed_time_between_patterns(
        logs=parsed_logsA,
        start_pattern="Receiver failed to acquire data",
        end_pattern="Signed data with private key")
    )
    dtimes_QKD_key_A = elapsed_time_between_patterns(
        logs=parsed_logsA,  # list of parsed logs
        start_pattern="Starting new HTTPS connection (1): 192.168.3.126",
        end_pattern="QKD key collected"
    )
    dtimes_PQC_key_A = elapsed_time_between_patterns(
        logs=parsed_logsA,  # list of parsed logs
        start_pattern="PQC key request initiated",
        end_pattern="PQC key collected"
    )
    dtimes_encrypt_A = elapsed_time_between_patterns(
        logs=parsed_logsA,  # list of parsed logs
        start_pattern="key collected",
        end_pattern="Encrypted data with key"
    )
    dtimes_sign_A = elapsed_time_between_patterns(
        logs=parsed_logsA,  # list of parsed logs
        start_pattern="Encrypted data with key",
        end_pattern="Signed data with private key"
    )

    # Collect time deltas between specific logs on RX
    dtimes_idle_B = elapsed_time_between_patterns(
        logs=parsed_logsB,
        start_pattern="POST /kem HTTP/1.1",
        end_pattern="Encrypted and signed payload received"
    )
    dtimes_rx_B = elapsed_time_between_patterns( # Crypto times with PQC + idle correction (between kem and data requests)
        logs=parsed_logsB,  # list of parsed logs
        start_pattern="Received ML-KEM request",
        end_pattern="POST /data HTTP/1.1"
    )
    dtimes_rx_B = [a - b for a, b in zip(dtimes_rx_B, dtimes_idle_B)]
    dtimes_rx_B += elapsed_time_between_patterns( # Crypto times with QKD
        logs=parsed_logsB,  # list of parsed logs
        start_pattern="Encrypted and signed payload received",
        end_pattern="172.22.112.1",
        condition_pattern="BB84 key collected"
    )
    if dtimes_rx_B is None:
        raise KeyboardInterrupt("Terminating: No data to work with in RX")
    dtimes_crypto_B = elapsed_time_between_patterns( # Crypto times with PQC + idle correction (between kem and data requests)
        logs=parsed_logsB,
        start_pattern="Received ML-KEM request",
        end_pattern="Decrypted data with key"
    )
    dtimes_crypto_B = [a - b for a, b in zip(dtimes_crypto_B, dtimes_idle_B)]
    dtimes_crypto_B += elapsed_time_between_patterns( # Crypto times with QKD
        logs=parsed_logsB,
        start_pattern="Encrypted and signed payload received",
        end_pattern="Decrypted data with key",
        condition_pattern="BB84 key collected"
    )
    dtimes_QKD_key_B = elapsed_time_between_patterns(
        logs=parsed_logsB,  # list of parsed logs
        start_pattern="Starting new HTTPS connection (1): 192.168.3.128",
        end_pattern="BB84 key collected"
    )
    dtimes_PQC_key_B = elapsed_time_between_patterns(
        logs=parsed_logsB,  # list of parsed logs
        start_pattern="Received ML-KEM request",
        end_pattern="POST /kem HTTP/1.1"
    )
    dtimes_encrypt_B = elapsed_time_between_patterns(
        logs=parsed_logsB,  # list of parsed logs
        start_pattern="key collected",
        end_pattern="Decrypted data with key"
    )
    dtimes_sign_B = elapsed_time_between_patterns(
        logs=parsed_logsB,  # list of parsed logs
        start_pattern="Encrypted and signed payload received",
        end_pattern="Verified signature"
    )

    # Collect transmission time of payload
    dtimes_payload = elapsed_time_between_patterns(
        logs=parsed_logsA,
        start_pattern="Starting new HTTP connection (1): 192.168.3.102",
        end_pattern="""http://192.168.3.102:8080 "POST /data HTTP/1.1" 200""",
        abort_pattern="Receiver failed"
    )
    # Correct for RX processing in payload transmission time
    dtimes_rx_B_all = elapsed_time_between_patterns(
        logs=parsed_logsB,
        start_pattern="Encrypted and signed payload received",
        end_pattern="""POST /data HTTP/1.1" 200"""
    )
    dtimes_payload = [a - b for a, b in zip(dtimes_payload, dtimes_rx_B_all)]

    # Calculated TX metrics
    # - Mean
    avg_time_tx_A = np.mean(dtimes_tx_A)
    avg_time_QKD_key_A = np.mean(dtimes_QKD_key_A)
    avg_time_PQC_key_A = np.mean(dtimes_PQC_key_A)
    avg_time_encrypt_A = np.mean(dtimes_encrypt_A)
    avg_time_sign_A = np.mean(dtimes_sign_A)
    avg_time_crypto_A = np.mean(dtimes_crypto_A)
    # - Standard deviation
    std_time_tx_A = np.std(dtimes_tx_A)
    std_time_QKD_key_A = np.std(dtimes_QKD_key_A)
    std_time_PQC_key_A = np.std(dtimes_PQC_key_A)
    std_time_encrypt_A = np.std(dtimes_encrypt_A)
    std_time_sign_A = np.std(dtimes_sign_A)
    std_time_crypto_A = np.std(dtimes_crypto_A)
    # - Max
    max_time_tx_A = np.max(dtimes_tx_A)
    max_time_QKD_key_A = np.max(dtimes_QKD_key_A)
    max_time_PQC_key_A = np.max(dtimes_PQC_key_A)
    max_time_encrypt_A = np.max(dtimes_encrypt_A)
    max_time_sign_A = np.max(dtimes_sign_A)
    max_time_crypto_A = np.max(dtimes_crypto_A)

    # - Error rates
    err_rate_tx_A_fatal = (num_errors_A_fatal / num_samples) * 1000
    err_rate_tx_A = (num_errors_A / num_samples) * 1000
    err_rate_QKD_key_A = (num_errors_A_QKD / num_samples) * 1000
    err_rate_PQC_key_A = (num_errors_A_PQC / num_samples) * 1000
    err_rate_encrypt_A = 0 # Placeholder
    err_rate_sign_A = 0 # Placeholder
    err_rate_crypto_A = err_rate_QKD_key_A + err_rate_PQC_key_A + err_rate_encrypt_A + err_rate_sign_A

    # Calculate RX metrics
    # - Mean
    avg_time_rx_B = np.mean(dtimes_rx_B)
    avg_time_QKD_key_B = np.mean(dtimes_QKD_key_B)
    avg_time_PQC_key_B = np.mean(dtimes_PQC_key_B)
    avg_time_encrypt_B = np.mean(dtimes_encrypt_B)
    avg_time_sign_B = np.mean(dtimes_sign_B)
    avg_time_crypto_B = np.mean(dtimes_crypto_B)
    # - Standard deviation
    std_time_rx_B = np.std(dtimes_rx_B)
    std_time_QKD_key_B = np.std(dtimes_QKD_key_B)
    std_time_PQC_key_B = np.std(dtimes_PQC_key_B)
    std_time_encrypt_B = np.std(dtimes_encrypt_B)
    std_time_sign_B = np.std(dtimes_sign_B)
    std_time_crypto_B = np.std(dtimes_crypto_B)
    # - Max
    max_time_rx_B = np.max(dtimes_rx_B)
    max_time_QKD_key_B = np.max(dtimes_QKD_key_B)
    max_time_PQC_key_B = np.max(dtimes_PQC_key_B)
    max_time_encrypt_B = np.max(dtimes_encrypt_B)
    max_time_sign_B = np.max(dtimes_sign_B)
    max_time_crypto_B = np.max(dtimes_crypto_B)
    # - Error rates
    err_rate_rx_B_fatal = (num_errors_B_fatal / num_errors_B) * 1000
    err_rate_rx_B = (num_errors_B / (num_errors_B + len(dtimes_rx_B))) * 1000
    err_rate_QKD_key_B = (num_errors_B_QKD / (num_errors_B + len(dtimes_rx_B))) * 1000
    err_rate_PQC_key_B = 0 # Placeholder
    err_rate_encrypt_B = 0 # Placeholder
    err_rate_sign_B = 0 # Placeholder
    err_rate_crypto_B = err_rate_QKD_key_B + err_rate_PQC_key_B + err_rate_encrypt_B + err_rate_sign_B

    # Calculate payload metrics
    # - Mean
    avg_time_payload = np.mean(dtimes_payload)
    # - Standard deviation
    std_time_payload = np.std(dtimes_payload)
    # - Max
    max_time_payload = np.max(dtimes_payload)
    # - Error rates
    err_rate_payload = (num_errors_A_data / (num_errors_A + len(dtimes_payload))) * 1000

    # Print TX metrics
    print("TX average latencies:")
    print("- Full payload processing:")
    print(f"-- Mean: {avg_time_tx_A:.2f} ms")
    print(f"-- Standard deviation: {std_time_tx_A:.2f} ms")
    print(f"-- Max: {max_time_tx_A:.0f} ms")
    print(f"-- Error rate: {err_rate_tx_A:.2f} ‰")
    print(f"-- Fatal error rate: {err_rate_tx_A_fatal:.2f} ‰")
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
    print("- QKD key collection:")
    print(f"-- Mean: {avg_time_QKD_key_A:.2f} ms")
    print(f"-- Standard deviation: {std_time_QKD_key_A:.2f} ms")
    print(f"-- Max: {max_time_QKD_key_A:.0f} ms")
    print(f"-- Error rate: {err_rate_QKD_key_A:.2f} ‰")
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
    print(f"-- Fatal error rate: {err_rate_rx_B_fatal:.2f} ‰")
    print("- Crypto processing:")
    print(f"-- Mean: {avg_time_crypto_B:.2f} ms")
    print(f"-- Standard deviation: {std_time_crypto_B:.2f} ms")
    print(f"-- Max: {max_time_crypto_B:.0f} ms")
    print(f"-- Error rate: {err_rate_crypto_B:.2f} ‰")
    print("- QKD key collection:")
    print(f"-- Mean: {avg_time_QKD_key_B:.2f} ms")
    print(f"-- Standard deviation: {std_time_QKD_key_B:.2f} ms")
    print(f"-- Max: {max_time_QKD_key_B:.0f} ms")
    print(f"-- Error rate: {err_rate_QKD_key_B:.2f} ‰")
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

    from test_alt import dtimes_tx_A as ML_KEM_768_deltas
    from test_alt_2 import dtimes_tx_A as BB84_deltas

    plot_time_deltas_ccdf_multi(
        [dtimes_tx_A, BB84_deltas, ML_KEM_768_deltas],
        labels=["Hybrid BB84 + ML-KEM-1024 (enhanced)","BB84","ML-KEM-768 (previous best)"],
        labels_short=["Hybrid","BB84","ML-KEM-768"],
        save_path="Latency_comparison.pdf",
        percentiles=[99],
        log_y=True
    )

    plot_time_deltas_ccdf(
        dtimes_tx_A,
        title="TX payload processing latency",
        save_path="TX_payload_processing_latency.pdf",
        percentiles=[99],
        log_y=True)
    plot_time_deltas_ccdf(
        dtimes_crypto_A,
        title="TX cryptography processing latency",
        save_path="TX_crypto_processing_latency.pdf",
        percentiles=[99],
        log_y=True)
    plot_time_deltas_ccdf(
        dtimes_QKD_key_A,
        title="TX QKD key exchange latency",
        save_path="TX_QKD_key_exchange_latency.pdf",
        percentiles=[99],
        log_y=True)
    plot_time_deltas_ccdf(
        dtimes_PQC_key_A,
        title="TX PQC key exchange latency",
        save_path="TX_PQC_key_exchange_latency.pdf",
        percentiles=[99],
        log_y=True)
    plot_time_deltas_ccdf(
        dtimes_encrypt_A,
        title="TX encryption latency",
        save_path="TX_encryption_latency.pdf",
        percentiles=[99],
        log_y=True)
    plot_time_deltas_ccdf(
        dtimes_sign_A,
        title="TX digital signature latency",
        save_path="TX_signature_latency.pdf",
        percentiles=[99],
        log_y=True)

    # Plot CDFs for the time deltas of RX
    plot_time_deltas_ccdf(
        dtimes_rx_B,
        title="RX payload processing latency",
        save_path="RX_payload_processing_latency.pdf",
        percentiles=[99],
        log_y=True)
    plot_time_deltas_ccdf(
        dtimes_crypto_B,
        title="RX cryptography processing latency",
        save_path="RX_crypto_latency.pdf",
        percentiles=[99],
        log_y=True)
    plot_time_deltas_ccdf(
        dtimes_QKD_key_B,
        title="RX QKD key exchange latency",
        save_path="RX_QKD_key_exchange_latency.pdf",
        percentiles=[99],
        log_y=True)
    plot_time_deltas_ccdf(
        dtimes_PQC_key_B,
        title="RX PQC key exchange latency",
        save_path="RX_PQC_key_exchange_latency.pdf",
        percentiles=[99],
        log_y=True)
    plot_time_deltas_ccdf(
        dtimes_encrypt_B,
        title="RX decryption latency",
        save_path="RX_encryption_latency.pdf",
        percentiles=[99],
        log_y=True)
    plot_time_deltas_ccdf(
        dtimes_sign_B,
        title="RX digital signature verification latency",
        save_path="RX_signature_latency.pdf",
        percentiles=[99],
        log_y=True)

    # Plot CDF for the time deltas of payload transmission
    plot_time_deltas_ccdf(
        dtimes_payload,
        title="Payload transmission latency",
        save_path="payload_transmission_latency.pdf",
        percentiles=[99],
        log_y=True)
