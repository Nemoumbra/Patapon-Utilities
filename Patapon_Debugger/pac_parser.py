# This is not a whole file, of course, but it contains enough info to understand the improvements
class PAC_parser:
    def __init__(self):
        self.templates: Dict[int, PAC_instruction_template] = {}
        self.jump_table_next_to_switch = True
        self.cmd_inxJmp_signature = 0x0
        self.find_unknown_instructions = True
        self.PAC_signature_to_name: Dict[int, str] = {}  # maybe not needed...
        self.templates: Dict[int, PAC_instruction_template] = {}
        self.instruction_heuristic: Callable[[int], bool] = defaultMayBeInstruction

        self.file: PAC_file = PAC_file()
        self.cur_offset = 0
        self.last_offset = 0
        self.last_was_instruction = False
        self.cur_signature = 0x0

    def mayBeInstruction(self, signature: int):
        return self.instruction_heuristic(signature)

    def acceptTemplates(self, PAC_instruction_templates: Dict[int, PAC_instruction_template]):
        self.templates = PAC_instruction_templates

    def findNextInstruction(self) -> bool:
        """
        Tries to advance cur_offset to the next instruction or unknown instruction\n
        :return: True on success (if the file suffix contains instructions or unknown instructions)
        """
        percent = 0x25
        while True:
            # TO DO: implement alignment settings for better parsing
            # TO DO: maybe request that self.cur_offset < self.file.size - 4 and play with it to omit checking?
            while self.cur_offset < self.file.size and self.file.raw_data[self.cur_offset] != percent:
                self.cur_offset += 1
            # Now let's make a check...
            if self.cur_offset + 3 < self.file.size:
                # We have enough bytes
                if self.find_unknown_instructions:
                    # Here we use some sort of heuristic
                    if self.mayBeInstruction(struct.unpack_from("<i", self.file.raw_data, self.cur_offset)[0]):
                        return True
                    else:
                        self.cur_offset += 1
                else:
                    # Here we test if the signature is known
                    if struct.unpack_from("<i", self.file.raw_data, self.cur_offset)[0] in self.templates:
                        return True
                    else:
                        self.cur_offset += 1
            else:
                # We don't have enough bytes
                return False

    def processMessageTable(self, raw: bytes):
        msg_table = PAC_message_table()
        msg_table.initialize_by_raw_data(raw)
        self.file.msg_tables[self.last_offset] = msg_table
        self.file.entities[self.last_offset] = msg_table

    def processLeftOutArgs(self, raw: bytes):
        instr_offset = self.file.entities_offsets[-1]
        args = Left_out_PAC_arguments(self.file.raw_data[instr_offset:], self.last_offset - instr_offset)
        self.file.left_out_PAC_arguments[self.last_offset] = args
        self.file.entities[self.last_offset] = args

    def processMemoryEntity(self, raw: bytes):
        entity = Memory_entity()
        entity.initialize_by_raw_data(raw)
        self.file.raw_entities[self.last_offset] = entity
        self.file.entities[self.last_offset] = entity

    def processRawData(self):
        """
        Attempts to create a raw entity (either MSG table, left out PAC arguments or Memory entity) \n
        from the range [self.cur_offset; self.last_offset) and advances self.last_offset
        :return: Does not return anything
        """
        if self.cur_offset == self.last_offset:
            return
        raw = self.file.raw_data[self.last_offset:self.cur_offset]
        if is_PAC_msg_table(raw):
            self.processMessageTable(raw)
        elif self.last_was_instruction and is_left_out_PAC_args(raw):
            self.processLeftOutArgs(raw)
        else:
            self.processMemoryEntity(raw)

        self.file.entities_offsets.append(self.last_offset)
        self.last_offset = self.cur_offset
        self.last_was_instruction = False

    def processInstruction(self):
        # self.cur_signature must be set before calling this
        self.file.entities_offsets.append(self.cur_offset)
        template = self.templates[self.cur_signature]
        instruction = PAC_instruction(self.file.raw_data, self.cur_offset, template)

        if self.cur_signature not in self.file.instructions:
            self.file.instructions[self.cur_signature] = {}
        self.file.instructions[self.cur_signature][self.cur_offset] = instruction

        self.file.entities[self.cur_offset] = instruction
        self.file.ordered_instructions[self.cur_offset] = instruction

        if instruction.cut_off:
            self.file.cut_instructions[self.cur_offset] = instruction
            self.file.cut_instructions_count += 1

        self.cur_offset += instruction.size

        # Special cmd_inxJmp case:
        if self.jump_table_next_to_switch and self.cur_signature == self.cmd_inxJmp_signature:
            res = self.findNextInstruction()
            self.processAddressTable()

        if template.PAC_params and template.PAC_params[-1].type == "string":
            self.fixAlignment()

    def processUnknownInstruction(self):
        # assumes self.last_offset == self.cur_offset
        self.cur_offset += 4
        res = self.findNextInstruction()

        # Unknown instruction will be from self.last_offset to self.cur_offset
        if not res:
            # No more instructions => the whole file suffix is an unknown instruction
            self.cur_offset = self.file.size

        raw = self.file.raw_data[self.last_offset:self.cur_offset]

        if self.cur_signature not in self.file.unknown_instructions:
            self.file.unknown_instructions[self.cur_signature] = {}

        unknown_instruction = Unknown_PAC_instruction(raw)
        self.file.unknown_instructions[self.cur_signature][self.last_offset] = unknown_instruction
        self.file.entities[self.last_offset] = unknown_instruction
        self.file.unknown_instructions_count += 1
        pass

    def fixAlignment(self):
        if self.cur_offset % 4 != 0:
            padding = Padding_bytes(4)
            padding_bytes_length = 4 - (self.cur_offset % 4)
            padding_raw = self.file.raw_data[self.cur_offset:self.cur_offset + padding_bytes_length]
            padding.initialize_by_raw_data(padding_raw)
            self.file.padding_bytes[self.cur_offset] = padding

            self.file.entities[self.cur_offset] = padding
            self.file.entities_offsets.append(self.cur_offset)
            self.cur_offset += padding_bytes_length
            pass

    def processAddressTable(self):
        if self.cur_offset == self.last_offset:
            return
        raw = self.file.raw_data[self.last_offset:self.cur_offset]
        table = Switch_case_table()
        table.initialize_by_raw_data(raw)

        self.file.entities_offsets.append(self.last_offset)
        self.file.entities[self.last_offset] = table
        self.file.switch_case_tables[self.last_offset] = table

    def parse(self):
        if self.file.raw_data == b"":
            raise RuntimeError("PAC file raw data is empty!")

        while self.cur_offset < self.file.size:
            res = self.findNextInstruction()
            if res:
                self.processRawData()
                # now self.last_offset == self.cur_offset
                signature = struct.unpack_from("<i", self.file.raw_data, self.cur_offset)[0]
                self.cur_signature = signature

                # self.find_unknown_instructions == False => the else clause is never executed
                if signature in self.templates:
                    self.processInstruction()
                else:
                    self.processUnknownInstruction()
            else:
                # No more instructions => self.file.raw_data[self.last_offset:] is a raw entity
                self.cur_offset = self.file.size
                self.processRawData()
        pass
