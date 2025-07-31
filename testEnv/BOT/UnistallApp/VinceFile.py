from cw_rpa import Logger

log = Logger()

aa = "Test"

log.info("Starting BOT")

if aa:
    log.result_success_message("Success")
else:
    log.result_failed_message("Failed")