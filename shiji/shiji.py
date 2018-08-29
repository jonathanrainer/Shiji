import subprocess
from pathlib import Path
from jinja2 import Template
import shutil
import os
from pyeda.util import clog2
from elftools.elf.elffile import ELFFile


class Shiji(object):

    def __init__(self, template_path, log_path, output_path, temporary_path, riscv_binary_prefix,
                 program_start, data_start, instruction_mem_size, data_mem_size, stack_size):
        self.config = Configuration(program_start, data_start, log_path, output_path, temporary_path,
                                    instruction_mem_size, data_mem_size, stack_size)
        self.utilities = Utilities()
        self.os_interface = OperatingSystemInterface(template_path, riscv_binary_prefix)
        self.template_interface = TemplateInterface()

    def run(self, benchmark, keep_temporary_files):
        self.os_interface.create_temp_folders(self.config.temporary_path)
        # Set up the linker file and boot script
        executable_file = self.os_interface.compile_benchmark(
            benchmark.absolute(),
            Path(self.config.temporary_path, "temp.o"),
            self.template_interface.create_link_and_boot_file(self.os_interface.template_base_path,
                                                              self.config.temporary_path,
                                                              self.utilities.hex_format(self.config.program_start),
                                                              self.utilities.hex_format(self.config.data_start),
                                                              self.config.instruction_mem_size,
                                                              self.config.data_mem_size,
                                                              self.config.stack_size)
        )
        # Extract the hex commands from the dumped file
        output_file_elements = self.os_interface.create_output_file_elements(executable_file)
        # Format them into templates
        instruction_memory_contents = self.template_interface.create_and_render_memory_template(
            str(self.os_interface.template_base_path / 'instruction_memory.template'),
            Path(self.config.output_path, "instruction_memory_mock_{0}.sv".format(benchmark.name.split(".")[0])),
            output_file_elements[0],
            self.config.program_start,
            self.config.instruction_mem_size,
            self.utilities.hex_format(4*(len(output_file_elements[0][-1][1]) + output_file_elements[0][-1][0] - 1))[2:],

        )
        data_memory_contents = self.template_interface.create_and_render_memory_template(
            str(self.os_interface.template_base_path / 'data_memory.template'),
            Path(self.config.output_path, "data_memory_mock_{0}.sv".format(benchmark.name.split(".")[0])),
            output_file_elements[1],
            self.config.data_start,
            self.config.data_mem_size+self.config.stack_size
        )
        self.os_interface.log_decompiled_file(executable_file.absolute(), (benchmark.name.split(".")[0]))
        if not keep_temporary_files:
            self.os_interface.clear_up_temporary_files(self.config.temporary_path)
        return instruction_memory_contents, data_memory_contents


class Utilities(object):

    @staticmethod
    def hex_format(integer):
        return "0x" + hex(int(integer))[2:]


class Configuration(object):

    def __init__(self, program_start, data_start, log_path, output_path, temporary_path, instruction_mem_size,
                 data_mem_size, stack_size):
        self.program_start = program_start
        self.data_start = data_start
        self.log_path = log_path
        self.output_path = output_path
        self.temporary_path = temporary_path
        self.instruction_mem_size = instruction_mem_size
        self.data_mem_size = data_mem_size
        self.stack_size = stack_size


class TemplateInterface(object):

    @staticmethod
    def create_and_render_memory_template(template_path, output_path, program_elements, data_start, mem_size,
                                          trap_address=None):
        if (max([int(x[0] + len(x[1]) - data_start // 4) for x in program_elements] + [1]) * 4) > mem_size:
            raise Exception("Memory Size Exceeded")
        num_words = 2 ** clog2(
            max([int(x[0] + len(x[1]) - data_start // 4) for x in program_elements] + [1]) * 4
        )
        array_offset = data_start // 4
        with open(template_path, 'r') as template_fp:
            template = Template(template_fp.read(), lstrip_blocks=True, trim_blocks=True)
        with open(str(output_path), "w") as output_file:
            output_file.write(template.render(
                program_elements=program_elements,
                num_words=num_words,
                array_offset=array_offset
            ))
        if trap_address:
            return output_path, num_words, trap_address
        else:
            return output_path, num_words

    @staticmethod
    def create_link_and_boot_file(template_base_path, temporary_path, program_start, data_start, instruction_mem_size,
                                  data_mem_size, stack_size):
        with open(str(template_base_path / 'boot.template')) as boot_file:
            template = Template(boot_file.read())
        boot_file_output_path = Path(temporary_path, "boot.S")
        with open(str(boot_file_output_path), "w") as output_boot_file:
            output_boot_file.write(template.render(
                program_start=program_start,
                stack_pointer_loc = hex(int(data_mem_size+stack_size)-4)
            ))
        with open(str(template_base_path / 'link.template')) as linker_file:
            template = Template(linker_file.read())
        linker_file_output_path = Path(temporary_path, "link.ld")
        with open(str(linker_file_output_path), "w") as output_linker_file:
            output_linker_file.write(template.render(
                program_start=program_start,
                data_start=data_start,
                instruction_mem_size = instruction_mem_size,
                data_mem_size = data_mem_size,
                stack_size = stack_size
                                     ))
        return [str(boot_file_output_path), str(linker_file_output_path)]


class ELFFileInterface(object):

    @staticmethod
    def extract_sections(searches, elf_file):
        results = []
        for section_name in searches:
            try:
                raw_bytes = bytearray(elf_file.get_section_by_name(section_name).data())
            except AttributeError:
                continue
            raw_bytes.reverse()
            hex_string = raw_bytes.hex()
            instructions = [hex_string[i:i + 8] for i in range(0, len(hex_string), 8)]
            instructions.reverse()
            results.append(
                (elf_file.get_section_by_name(section_name).header["sh_addr"] // 4,
                 instructions)
            )
        return results


class OperatingSystemInterface(object):

    def __init__(self, template_base_path, riscv_binary_prefix):
        self.template_base_path = template_base_path
        self.riscv_binary_prefix = riscv_binary_prefix
        self.elf_file_interface = ELFFileInterface()

    @staticmethod
    def create_temp_folders(temp_path):
        os.makedirs(str(temp_path.absolute()), exist_ok=True)

    def create_output_file_elements(self, output_file):
        with open(str(output_file.absolute()), 'rb') as elf_fp:
            elf_file = ELFFile(elf_fp)  # type: ELFFile
            instruction_memory_contents = self.elf_file_interface.extract_sections(
                [".reset", ".illegal_instruction", ".text"], elf_file
            )
            data_memory_contents = self.elf_file_interface.extract_sections(
                [".rodata", ".bss", ".data"], elf_file
            )
        return instruction_memory_contents, data_memory_contents

    def compile_benchmark(self, benchmark_path, executable_file, paths):
        #  Compile it
        subprocess.run(
            "{0}riscv32-unknown-elf-gcc -nostartfiles {1} {2} -T {3} -o {4}".format(
                self.riscv_binary_prefix,
                paths[0],
                benchmark_path,
                paths[1],
                executable_file
            ), shell=True
        )
        return executable_file

    def log_decompiled_file(self, executable_path, benchmark_name):
        subprocess.run(
            "{0}riscv32-unknown-elf-objdump -D -S {1} > {2}".format(
                self.riscv_binary_prefix,
                executable_path,
                Path("logs", "{0}-disassembled.txt".format(benchmark_name)).absolute()
            ), shell=True
        )

    @staticmethod
    def clear_up_temporary_files(temp_path):
        shutil.rmtree(str(temp_path))


if __name__ == "__main__":
    temp_folder = Path("temp")
    system = Shiji(
        Path("templates"), Path("logs"), Path("output"), temp_folder , "/opt/riscv/bin/", 256, 65536, 32768, 32768,
        32768
    )
    system.run(Path("benchmarks", "fdct.c"), True)
