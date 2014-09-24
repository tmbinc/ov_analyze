import sys, struct, copy, os

class Element:
  id = 0

  def __init__(self, type, claims = "", **content):
    self.type = type
    self.id = Element.id
    Element.id += 1
    self.claimed = False
    self.claims = claims
    self.claimed_by = []
    self.__dict__.update(content)
    self.content = content
  
  def claim(self):
    return "CLAIM:%s" % ','.join("%d" % c for c in self.claimed_by) if len(self.claimed_by) else ""
  
  def __repr__(self):
    return "<%d %s %s %r>" % (self.id, self.type, self.claim(), self.content)

class Packet(Element):
  def __init__(self, name, **content):
    Element.__init__(self, "PACKET", token = name, **content)

  def __repr__(self):
    return "<%d %s %s>" % (self.id, self.token, self.claim())

def parse_data(str):
  return {"data": bytes.fromhex(str.replace(" ", ""))[:-2]}

def parse_endpoint(str):
  address, endpoint = str.split(".")
  return {"address": int(address), "endpoint": int(endpoint)}

class Error(Element):
  def __init__(self, error):
    Element.__init__(self, "ERROR", error = error)

class Timestamp(Element):
  def __init__(self, ts):
    Element.__init__(self, "TIMESTAMP", timestamp = ts)

def parse(fn):
  cnt = 0
  for r in open(fn):
    r = r.strip()
    
    yield Timestamp(cnt)
    cnt += 1
    
    if cnt == 1: continue

    spos = r.find("]", r.find("]", r.find("]") + 1) + 1) + 2
    r = r[spos:]
    token = r[0:5].strip()

    if not token:
      yield Error("empty")
      continue
    
    if token == "SETUP":
      yield Packet("SETUP", **parse_endpoint(r[7:]))
    elif token in ["DATA0", "DATA1", "DATA"]:
      yield Packet(token, **parse_data(r[7:]))
    elif token == "ACK":
      yield Packet("ACK")
    elif token == "NAK":
      yield Packet("NAK")
    elif token == "IN":
      yield Packet("IN", **parse_endpoint(r[7:]))
    elif token == "OUT":
      yield Packet("OUT", **parse_endpoint(r[7:]))
    elif token == "PING":
      yield Packet("PING", **parse_endpoint(r[7:]))
    elif token == "NYET":
      yield Packet("NYET")
    elif token == "STALL":
      yield Packet("STALL")
    else:
      assert False, token

active_elements = []

parser = parse(sys.argv[1])

all_elements = []

class StateMachine:

  OPCODE_IF, OPCODE_FORK, OPCODE_MARK, OPCODE_CAPTURE, OPCODE_APPEND, OPCODE_NEXT, OPCODE_EMIT, OPCODE_COMPLAIN = range(8)

  def __init__(self, name, filter):
    self.name = name
    self.transitions = {}
    self.current_transition = None
    self.claimed = []
    self.result = {}
    self.current_state = "Initial"
    self.filter = filter
  
  def __repr__(self):
    return "<StateMachine %s, %s, %r>" % (self.name, self.current_state, self.result)
  
  def add_transition(self, name):
    print("AddTransition %r" % name)
    self.current_transition = []
    self.transitions.setdefault(name, []).append(self.current_transition)
  
  def add_if(self, type, comp, values):
    self.current_transition.append((self.OPCODE_IF, type, comp, values))
  
  def add_fork(self):
    self.current_transition.append((self.OPCODE_FORK,))
  
  def add_mark(self):
    self.current_transition.append((self.OPCODE_MARK,))
  
  def add_capture(self, target, source):
    self.current_transition.append((self.OPCODE_CAPTURE, target, source))

  def add_append(self, target, source):
    self.current_transition.append((self.OPCODE_APPEND, target, source))
  
  def add_next(self, state):
    self.current_transition.append((self.OPCODE_NEXT, state))

  def add_emit(self):
    self.current_transition.append((self.OPCODE_EMIT,))

  def add_complain(self):
    self.current_transition.append((self.OPCODE_COMPLAIN,))

  def consume(self, element):
  
    if element.type not in self.filter:
      return [self],[]
  
    match = False
    
    self.trace_current_element = element
    
    res_state_machines = []
    res_elements = []

    for transition in self.transitions[self.current_state]:
      self.trace("checking transition", transition)
      
      match = True
      
      for (opcode, *args) in transition:
        if opcode == self.OPCODE_IF:
          comp_type = args[1]
          comp = element.__dict__[args[0]]
          values = args[2]
          assert comp_type in ("==", "!=")
          
          if comp_type == "==":
            res = False
          else:
            res = True

          self.trace("IF <%r> <%s> <%r> - %d" % (args[0], comp_type, values, res))
          
          for v in values:
            if len(v) >= 2 and v[0] == '"' and v[-1] == '"':
              lit = v[1:-1]
            elif v[0] == '"':
              raise Exception("invalid literal", v)
            else:
              assert v in self.result, ("item not found", v)
              lit = self.result[v]
            
            if args[0] == "data": # FAKE FAKE FAKE
              lit = bytes.fromhex(lit)
              print("FAKE IT", repr(lit), repr(comp))
            
            if comp_type == "==":
              res = res or comp == lit
            elif comp_type == "!=":
              res = res and comp != lit

          if not res:
            match = False
            break
        elif opcode == self.OPCODE_FORK:
          self.trace("FORK")
          new_state_machine = copy.copy(self)
          new_state_machine.claimed = list(self.claimed)
          new_state_machine.result = dict(self.result)
          res_state_machines.append(new_state_machine)
          
        elif opcode == self.OPCODE_MARK:
          self.trace("MARK")
          assert not element.claimed, "already claimed"
          element.claimed = True
          self.claimed.append(element)
        elif opcode == self.OPCODE_CAPTURE:
          target = args[0]
          source = element.__dict__[args[1]] if args[1] is not None else b""
          self.trace("CAPTURE - %s := %r" % (target, source))
          self.result[target] = source
        elif opcode == self.OPCODE_APPEND:
          target = args[0]
          source = element.__dict__[args[1]]
          self.trace("APPEND - %s += %r" % (target, source))
          self.result[target] += source
        elif opcode == self.OPCODE_NEXT:
          self.current_state = args[0]
          self.trace("NEXT %s" % self.current_state)
        elif opcode == self.OPCODE_EMIT:
          self.trace("EMIT", self)
          res_elements.append(Element(self.name, claims = self.claimed, **self.result))
          match = False
        elif opcode == self.OPCODE_COMPLAIN:
          assert False, "complain"
      
      self.trace("DONE WITH TRANSITION", match)
      if match or len(res_elements):
        break
        
    if match:
      assert not len(res_elements)
      res_state_machines.append(self)
    else:
      assert len(res_elements), "state machine fell through without emitting from %s (%s < %s)" % (self.current_state, element, self.result)
      #print("KILL:", self, res_state_machines)
    
    return res_state_machines[::-1], res_elements

  def trace(self, *x):
    #print("%r (with %r):" % (self, self.trace_current_element), *x)
    pass
    
active_state_machines = []
current_state_machine = None

def read_states():
  for l in open(os.path.join(os.path.dirname(os.path.realpath(__file__)), "analyze.states")):
    l = l[:-1]
    
    if not l.strip():
      continue
    
    if l.strip()[0] == "#":
      continue
    
    if l.startswith("    "):
      cmd, *args = l.strip().split()
      
      if cmd == "if":
        current_state_machine.add_if(args[0], args[1], args[2:])
      elif cmd == "fork":
        current_state_machine.add_fork()
      elif cmd == "mark":
        current_state_machine.add_mark()
      elif cmd == "capture":
        current_state_machine.add_capture(args[0], args[1] if len(args) > 1 else None)
      elif cmd == "append":
        current_state_machine.add_append(args[0], args[1])
      elif cmd == "next":
        current_state_machine.add_next(args[0])
      elif cmd == "complain":
        current_state_machine.add_complain()
      elif cmd == "emit":
        current_state_machine.add_emit()
      else:
        assert False, cmd
    elif l.startswith("  "):
      current_state_machine.add_transition(l[2:])
    else:
      state_machine_name, state_machine_filter = l.split(" ")
      current_state_machine = StateMachine(state_machine_name, state_machine_filter.split(","))
      active_state_machines.append(current_state_machine)

read_states()
    
print(active_state_machines)
    
def dump(e, id = 0):
  print("--" * id + " %r" % e)
  for y in e.claims:
    dump(y, id + 1)


try:
  while True:
    e = active_elements.pop(0) if len(active_elements) else next(parser)
    
#    print("********** EUT: %r" % e)
#    print(">>>>>>>>>> active state machines")
#    for sm in active_state_machines:
#      print("  ",sm)
#    print("<<<<<<<<<< active state machines")
    new_state_machines = []
    for state_machine in active_state_machines:
      if not e.claimed:
#        print("-> %s .consume %s" % (state_machine, e))
        res_state_machines, res_elements = state_machine.consume(e)
      else:
        res_state_machines = [state_machine]
        res_elements = []
      active_elements += res_elements
#      if res_elements:
#        print("emitted: %r" % active_elements)
      new_state_machines += res_state_machines
    if not e.claimed and not e.type == "TIMESTAMP":
      dump(e)
      

    active_state_machines = new_state_machines
      

except StopIteration:
  pass

  
