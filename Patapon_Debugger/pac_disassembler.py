# This code is cropped from a bigger file
def disassemble_to_file(file: PAC_file, where_to: Path):
    with open(where_to, "w", encoding="utf-8") as output:
        for file_offset in file.entities_offsets:
            hex_offset = f"{file_offset:08X}  "
            output.write(hex_offset)

            entity_object = file.entities[file_offset]
            entity_object_type = type(entity_object)
            if entity_object_type is Memory_entity:
                entity = cast(Memory_entity, entity_object)
                output.write(f"Memory entity: size = {entity.size} bytes")
                try:
                    shift_jis_data = read_shift_jis_from_bytes(entity.raw_data, 0, entity.size)
                    output.write(f", shift-jis = ({shift_jis_data})")
                except UnicodeDecodeError:
                    print(f"Failed to decode shift-jis at {file_offset:X} (that's not a fatal error, don't worry)")
                except Exception as e:
                    print(f"Error at {file_offset:X}", e)
            elif entity_object_type is Padding_bytes:
                padding = cast(Padding_bytes, entity_object)
                output.write(
                    f"Padding bytes: count = {padding.size}, all zeroes = {padding.zeroes_only}, "
                    f"machine word length = {padding.machine_word_length}"
                )
            elif entity_object_type is PAC_instruction:
                instruction = cast(PAC_instruction, entity_object)
                output.write(f"{instruction.signature:X}:{instruction.name}(")
                args_count = len(instruction.ordered_PAC_params)
                if args_count > 0:
                    for param, value in instruction.ordered_PAC_params[0:-1]:
                        output.write(f"{{{param.type}; {param.name}}}=")
                        if isinstance(value, int):
                            output.write(f"{value:X}, ")
                        elif isinstance(value, str):
                            output.write("\"" + value.replace("\x00", "") + "\", ")
                        else:
                            output.write(f"{value}, ")
                    # last argument
                    param, value = instruction.ordered_PAC_params[-1]
                    output.write(f"{{{param.type}; {param.name}}}=")
                    if isinstance(value, int):
                        output.write(f"{value:X}")
                    elif isinstance(value, str):
                        output.write("\"" + value.replace("\x00", "") + "\"")
                    else:
                        output.write(f"{value}")
                output.write(")")
                if instruction.cut_off:
                    output.write(" [Warning, instruction unexpectedly ends!]")
            elif entity_object_type is Unknown_PAC_instruction:
                unknown_instruction = cast(Unknown_PAC_instruction, entity_object)
                output.write(
                    f"{unknown_instruction.signature:X}(Unknown): size = {unknown_instruction.size}"
                )
            elif entity_object_type is Switch_case_table:
                switch_case_table = cast(Switch_case_table, entity_object)
                output.write(
                    f"Switch-case table: size = {switch_case_table.size} bytes, "
                    f"branches count = {len(switch_case_table.branches)}, addresses: ("
                )
                for branch in switch_case_table.branches[0:-1]:
                    output.write(f"{branch:X}, ")
                output.write(f"{switch_case_table.branches[-1]:X})")
            elif entity_object_type is PAC_message_table:
                message_table = cast(PAC_message_table, entity_object)
                output.write(
                    f"Message table: size = {message_table.size} bytes, message count = {message_table.msg_count}"
                )
            elif entity_object_type is Left_out_PAC_arguments:
                left_args = cast(Left_out_PAC_arguments, entity_object)
                output.write(
                    f"Potential left out PAC args: size = {left_args.size} bytes, "
                    f"supposed full size of the instruction = {left_args.supposed_size}"
                )
            output.write("\n")
        pass


def disassemble_pacs_in_directory(directory: Path, instruction_set: Path):
    pac_parser = PataponDebugger()
    pac_parser.read_instruction_set(str(instruction_set))
    files = directory.glob("*.pac")
    for path in files:
        if path.is_dir():
            continue
        try:
            file = PAC_file()
            full_path = directory / path.name
            file.initialize_by_raw_data(load_file_by_path(str(full_path)))
            pac_parser.parse_PAC_file(file)
            print(f"{path.name} parsed successfully!")
            disassemble_to_file(file, directory / (path.name + ".txt"))
        except Exception as e:
            print(e)
    print("Done!")
    exit()
    pass
