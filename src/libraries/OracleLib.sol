// SPDX-License-Identifier: MIT
pragma solidity ^0.8.18;

/**
 * @title OracleLib
 * @author BatuBlockDev
 * @notice Library that adds staleness checks to Chainlink price feeds.
 * Wraps latestRoundData with a timeout validation to prevent using
 * outdated prices. Used by PayMaster to get CELO/USD prices safely.
 */

// ////////////////////////////////////////
// ///////////// IMPORTS /////////////////
// ////////////////////////////////////////

import {AggregatorV3Interface} from "lib/chainlink-brownie-contracts/contracts/src/v0.8/interfaces/AggregatorV3Interface.sol";

// ////////////////////////////////////////
// /////////////// ERRORS /////////////////
// ////////////////////////////////////////

/// @notice Reverts when the price feed has not been updated within the timeout
error OracleLib_StalePrice();

library OracleLib {

// ////////////////////////////////////////
// //////////// STATE VARIABLES ////////////
// ////////////////////////////////////////

    /// @notice Maximum time allowed since last price update (3 hours)
    uint256 private constant TIMEOUT = 3 hours;

// ////////////////////////////////////////
// /////////// INTERNAL FUNCTIONS /////////
// ////////////////////////////////////////

    /**
     * @param priceFeed The Chainlink AggregatorV3Interface to read from
     * @return roundId The round ID of the price
     * @return answer The price answer
     * @return startedAt The timestamp when the round started
     * @return updatedAt The timestamp when the round was last updated
     * @return answeredInRound The round in which the answer was computed
     * @notice Reads the latest round data from the price feed and reverts
     * if the data is stale (older than TIMEOUT).
     */
    function staleCheckLastTestRoundData(
        AggregatorV3Interface priceFeed
    ) internal view returns (uint80, int256, uint256, uint256, uint80) {
        (
            uint80 roundId,
            int256 answer,
            uint256 startedAt,
            uint256 updatedAt,
            uint80 answeredInRound
        ) = priceFeed.latestRoundData();
        uint256 sencondsSinceUpdate = block.timestamp - updatedAt;
        if (sencondsSinceUpdate > TIMEOUT) revert OracleLib_StalePrice();
        return (roundId, answer, startedAt, updatedAt, answeredInRound);
    }
}