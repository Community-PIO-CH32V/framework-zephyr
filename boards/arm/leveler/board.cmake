board_runner_args(stm32cubeprogrammer "--port=swd" "--reset=hw")

include(${ZEPHYR_BASE}/boards/common/stm32cubeprogrammer.board.cmake)
include(${ZEPHYR_BASE}/boards/common/openocd.board.cmake)
