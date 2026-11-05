#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum VpnState { Disconnected, Connecting, Connected, KillswitchEngaged }

#[derive(Debug)]
pub struct VpnManager {
    state: VpnState,
}

impl VpnManager {
    pub fn new() -> Self { Self { state: VpnState::Disconnected } }
    pub fn connect(&mut self) { self.state = VpnState::Connected; }
    pub fn disconnect(&mut self) { self.state = VpnState::Disconnected; }
    pub fn engage_killswitch(&mut self) { self.state = VpnState::KillswitchEngaged; }
    pub fn get_state(&self) -> VpnState { self.state }
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn test_vpn_manager_state_flow_aaa() {
        // Arrange
        let mut vpn = VpnManager::new();
        assert_eq!(vpn.get_state(), VpnState::Disconnected);
        // Act
        vpn.connect();
        assert_eq!(vpn.get_state(), VpnState::Connected);
        vpn.engage_killswitch();
        // Assert
        assert_eq!(vpn.get_state(), VpnState::KillswitchEngaged);
    }
}
