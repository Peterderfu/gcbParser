#ref https://python-statemachine.readthedocs.io/en/latest/readme.html
from statemachine import StateMachine, State
from statemachine.statemachine import Transition

CONFIG_SYSTEM_INTERFACE = "config system interface"
EDIT_INTERFACE_NAME = "edit <interface_name>"
SET_ALLOWACCESS = "set allowaccess <access_types>"
    
class gcbFortigateMachine(StateMachine):
    state_00 = State('State_00',initial=True)
    state_01 = State('State_01',value="config system interface")
    state_10 = State('State_10',value="edit <interface_name>")
    state_47 = State('State_47_F',value="set allowaccess <access_types>")
    state_48 = State('State_48')
    state_49 = State('State_49')
    state_50 = State('State_50')
    state_51 = State('State_51')
    state_52 = State('State_52')
    
    t_00_01 = state_00.to(state_01)
    t_01_10 = state_01.to(state_10)
    t_10_47 = state_10.to(state_47)
    Transition

#     t_01_48 = state_01.to(state_48)
#     t_01_49 = state_01.to(state_49)
#     t_01_50 = state_01.to(state_50)
#     t_01_51 = state_01.to(state_51)
#     t_01_52 = state_01.to(state_52)
    
#     state_02 = State('State_02')
#     state_03 = State('State_03')
#     state_04 = State('State_04')
#     state_05 = State('State_05')
#     state_06 = State('State_06')
#     state_ = State('State_07')
#     state_ = State('State_08')
#     state_ = State('State_09')
#     state_ = State('State_10')
#     state_ = State('State_11')
#     state_ = State('State_12')
#     state_ = State('State_13')
#     state_ = State('State_14')
#     state_ = State('State_')
#     state_ = State('State_')
#     state_ = State('State_')
#     state_ = State('State_')
#     state_ = State('State_')
#     state_ = State('State_')
#     state_ = State('State_')
    def on_t_10_47(self):
        cmdLine = []
        preState = self.allowed_transitions[0].source
#         while(not preState.initial):
#             cmdLine.append(preState.value)
#             preState = 
        print(self.transitions[-1].destinations[0].value)
    def on_t_01_10(self):
        print(self.transitions[-1].destinations[0].value)
    def on_t_00_01(self):
        print(self.transitions[-1].destinations[0].value)
    
       



ss = gcbFortigateMachine()
assert(ss.current_state)

line = "config system interface"
if line == CONFIG_SYSTEM_INTERFACE:
    ss.run('t_00_01')
line = "edit <interface_name>"
if line == EDIT_INTERFACE_NAME:
    ss.run('t_01_10')
line =  "set allowaccess <access_types>"
if line == SET_ALLOWACCESS:
    ss.run('t_10_47')
    
