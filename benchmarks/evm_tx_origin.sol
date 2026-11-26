contract Benchmark {
    function authorized() public view returns (bool) {
        return tx.origin == msg.sender;
    }
}
