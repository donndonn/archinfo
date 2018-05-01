import logging

l = logging.getLogger("archinfo.arch_sparc64")

try:
    import capstone as _capstone
except ImportError:
    _capstone = None

try:
    import keystone as _keystone
except ImportError:
    _keystone = None

try:
    import unicorn as _unicorn
except ImportError:
    _unicorn = None

from .arch import Arch, register_arch, Endness
from .tls import TLSArchInfo
from .archerror import ArchError


class ArchSPARC64(Arch):
    def __init__(self, endness="Iend_BE"):
        super(ArchSPARC64, self).__init__(endness)
        if endness == Endness.BE:
            self.function_prologs = {
                r"\x94\x21[\x00-\xff]{2}\x7c\x08\x02\xa6",  # stwu r1, -off(r1); mflr r0
                r"(?!\x94\x21[\x00-\xff]{2})\x7c\x08\x02\xa6",  # mflr r0
                r"\xf8\x61[\x00-\xff]{2}",  # std r3, -off(r1)
            }
            self.function_epilogs = {
                r"[\x00-\xff]{2}\x03\xa6([\x00-\xff]{4}){0,6}\x4e\x80\x00\x20"  # mtlr reg; ... ; blr
            }
            self.triplet = 'sparc64-linux-gnu'

    bits = 64
    vex_arch = None
    name = "SPARC64"
    vex_arch = "VexArchSPARC64"
    linux_name = 'SPARC64'
    max_inst_bytes = 4
    ip_offset = 1296
    sp_offset = 64  # ??

    ########
    #  TODO: chek if these are correct
    qemu_name = 'sparc64'
    ida_processor = 'sparc64'
    triplet = 'sparc64-linux-gnu'
    bp_offset = 264     # ??
    ret_offset = 40     # ??
    lr_offset = 1304    # ??
    initial_sp = 0xffffffffff000000
    function_prologs = {
        r"[\x00-\xff]{2}\x21\x94\xa6\x02\x08\x7c",  # stwu r1, -off(r1); mflr r0
    }
    function_epilogs = {
        r"\xa6\x03[\x00-\xff]{2}([\x00-\xff]{4}){0,6}\x20\x00\x80\x4e"  # mtlr reg; ... ; blr
    }
    ########

    syscall_num_offset = 16
    call_pushes_ret = False
    stack_change = -4

    sizeof = {'short': 16, 'int': 32, 'long': 64, 'long long': 64}

    ret_instruction = ""
    nop_instruction = ""
    instruction_alignment = 4
    persistent_regs = ['r2']



    default_register_values = [
        ('sp', initial_sp, True, 'global')  # the stack
    ]
    entry_register_values = {
        'r2': 'toc',
        'r3': 'argc',
        'r4': 'argv',
        'r5': 'envp',
        'r6': 'auxv',
        'r7': 'ld_destructor'
    }

    default_symbolic_registers = ['sp', 'r0', 'r1', 'r2', 'r3', 'r4', 'r5', 'r6', 'r7', 'r8', 'r9', 'r10', 'r11', 'r12',
                                  'r13', 'r14', 'r15', 'r16', 'r17', 'r18', 'r19', 'r20', 'r21', 'r22', 'r23', 'r24',
                                  'r25', 'r26', 'r27', 'r28', 'r29', 'r30', 'r31']

    register_names = {
        # General purpose registers
        16: 'r0',  # zero
        24: 'r1',
        32: 'r2',
        40: 'r3',
        48: 'r4',
        56: 'r5',
        64: 'r6',
        72: 'r7',
        80: 'r8',
        88: 'r9',
        96: 'r10',
        104: 'r11',
        112: 'r12',
        120: 'r13',
        128: 'r14',  # sp
        136: 'r15',  # The CALL instruction writes its own address into register r[15]
        144: 'r16',
        152: 'r17',
        160: 'r18',
        168: 'r19',
        176: 'r20',
        184: 'r21',
        192: 'r22',
        200: 'r23',
        208: 'r24',
        216: 'r25',
        224: 'r26',
        232: 'r27',
        240: 'r28',
        248: 'r29',
        256: 'r30',
        264: 'r31',
        # FPU regs
        272: 'f0',
        276: 'f1',
        280: 'f2',
        284: 'f3',
        288: 'f4',
        292: 'f5',
        296: 'f6',
        300: 'f7',
        304: 'f8',
        308: 'f9',
        312: 'f10',
        316: 'f11',
        320: 'f12',
        324: 'f13',
        328: 'f14',
        332: 'f15',
        336: 'f16',
        340: 'f17',
        344: 'f18',
        348: 'f19',
        352: 'f20',
        356: 'f21',
        360: 'f22',
        364: 'f23',
        368: 'f24',
        372: 'f25',
        376: 'f26',
        380: 'f27',
        384: 'f28',
        388: 'f29',
        392: 'f30',
        396: 'f31',
        400: 'd32',
        408: 'd34',
        416: 'd36',
        424: 'd38',
        432: 'd40',
        440: 'd42',
        448: 'd44',
        456: 'd46',
        464: 'd48',
        472: 'd50',
        480: 'd52',
        488: 'd54',
        496: 'd56',
        504: 'd58',
        512: 'd60',
        520: 'd62',
        # Program counters
        528: 'pc',
        536: 'npc',
        544: 'y',  # high 32 bits always read 0
        552: 'asi',
        560: 'fprs',
        568: 'GSR_align',  # GSR.align (3 bits)
        572: 'GSR_mask',  # GSR.mask (32 bits)
        #    For clflush/clinval: record start and length of area
        576: 'cmstart',
        584: 'cmlen',
        #  ccr helper regs
        592: 'cc_op',
        600: 'cc_dep1',
        608: 'cc_dep2',
        616: 'cc_cdep',
        # FSR helper regs
        624: 'fsr_rd',  # FSR.rd in IRRoundingMode representation
        632: 'fsr_fcc',  # all FSR.fcc fields
        # FSR.cexc helper regs
        640: 'fsr_cexc_op',
        648: 'fsr_cexc_dep1_hi',  # 128-bit wide DEP1
        656: 'fsr_cexc_dep1_lo',
        664: 'fsr_cexc_dep2_hi',  # 128-bit wide DEP2
        672: 'fsr_cexc_dep2_lo',
        680: 'fsr_cexc_ndep',   # FSR.rd valid at that moment

        688: 'nraddr',
        696: 'emnote',
        700: 'pad1',
        704: 'scratchpad',

        #  The following are used to save host registers during the execution of
        #        an unrecognized instruction
        712: 'host_fp',
        720: 'host_sp',
        728: 'host_07'

    }

    registers = {

        'g0': (16, 8),
        'g1': (24, 8),
        'g2': (32, 8),
        'g3': (40, 8),
        'g4': (48, 8),
        'g5': (56, 8),
        'g6': (64, 8),
        'g7': (72, 8),
        'o0': (80, 8),
        'o1': (88, 8),
        'o2': (96, 8),
        'o3': (104, 8),
        'o4': (112, 8),
        'o5': (120, 8),
        'o6': (128, 8),
        'sp': (128, 8),
        'o7': (136, 8),
        'l0': (144, 8),
        'l1': (152, 8),
        'l2': (160, 8),
        'l3': (168, 8),
        'l4': (176, 8),
        'l5': (184, 8),
        'l6': (192, 8),
        'l7': (200, 8),
        'i0': (208, 8),
        'i1': (216, 8),
        'i2': (224, 8),
        'i3': (232, 8),
        'i4': (240, 8),
        'i5': (248, 8),
        'i6': (256, 8),
        'i7': (264, 8),
        'r0': (16, 8),
        'r1': (24, 8),
        'r2': (32, 8),
        'r3': (40, 8),
        'r4': (48, 8),
        'r5': (56, 8),
        'r6': (64, 8),
        'r7': (72, 8),
        'r8': (80, 8),
        'r9': (88, 8),
        'r10': (96, 8),
        'r11': (104, 8),
        'r12': (112, 8),
        'r13': (120, 8),
        'r14': (128, 8),
        'r15': (136, 8),
        'r16': (144, 8),
        'r17': (152, 8),
        'r18': (160, 8),
        'r19': (168, 8),
        'r20': (176, 8),
        'r21': (184, 8),
        'r22': (192, 8),
        'r23': (200, 8),
        'r24': (208, 8),
        'r25': (216, 8),
        'r26': (224, 8),
        'r27': (232, 8),
        'r28': (240, 8),
        'r29': (248, 8),
        'r30': (256, 8),
        'r31': (264, 8),

        'f0': (272, 4),
        'f1': (276, 4),
        'f2': (280, 4),
        'f3': (284, 4),
        'f4': (288, 4),
        'f5': (292, 4),
        'f6': (296, 4),
        'f7': (300, 4),
        'f8': (304, 4),
        'f9': (308, 4),
        'f10': (312, 4),
        'f11': (316, 4),
        'f12': (320, 4),
        'f13': (324, 4),
        'f14': (328, 4),
        'f15': (332, 4),
        'f16': (336, 4),
        'f17': (340, 4),
        'f18': (344, 4),
        'f19': (348, 4),
        'f20': (352, 4),
        'f21': (356, 4),
        'f22': (360, 4),
        'f23': (364, 4),
        'f24': (368, 4),
        'f25': (372, 4),
        'f26': (376, 4),
        'f27': (380, 4),
        'f28': (384, 4),
        'f29': (388, 4),
        'f30': (392, 4),
        'f31': (396, 4),
        'd0': (272, 8),
        'd2': (280, 8),
        'd4': (288, 8),
        'd6': (296, 8),
        'd8': (304, 8),
        'd10': (312, 8),
        'd12': (320, 8),
        'd14': (328, 8),
        'd16': (336, 8),
        'd18': (344, 8),
        'd20': (352, 8),
        'd22': (360, 8),
        'd24': (368, 8),
        'd26': (376, 8),
        'd28': (384, 8),
        'd30': (392, 8),
        'd32': (400, 8),
        'd34': (408, 8),
        'd36': (416, 8),
        'd38': (424, 8),
        'd40': (432, 8),
        'd42': (440, 8),
        'd44': (448, 8),
        'd46': (456, 8),
        'd48': (464, 8),
        'd50': (472, 8),
        'd52': (480, 8),
        'd54': (488, 8),
        'd56': (496, 8),
        'd58': (504, 8),
        'd60': (512, 8),
        'd62': (520, 8),
        'pc': (528, 8),
        'ip': (528, 8),
        'npc': (536, 8),
        'y': (544, 8),
        'asi': (552,),
        'fprs': (560,),
        'GSR_align': (568,),
        'GSR_mask': (572,),
        'cmstart': (576,),
        'cmlen': (584,),
        'cc_op': (592,),
        'cc_dep1': (600,),
        'cc_dep2': (608,),
        'cc_cdep': (616,),
        'fsr_rd': (624,),
        'fsr_fcc': (632,),
        'fsr_cexc_op': (640,),
        'fsr_cexc_dep1_hi': (648,),
        'fsr_cexc_dep1_lo': (656,),
        'fsr_cexc_dep2_hi': (664,),
        'fsr_cexc_dep2_lo': (672,),
        'fsr_cexc_ndep': (680,),
        'nraddr': (688,),
        'emnote': (696,),
        'pad1': (700,),
        'scratchpad': (704,),
        'host_fp': (712,),
        'host_sp': (720,),
        'host_07': (728,),
    }

    argument_registers = {
        registers['r2'][0],
        registers['r3'][0],
        registers['r4'][0],
        registers['r5'][0],
        registers['r6'][0],
        registers['r7'][0],
        registers['r8'][0],
        registers['r9'][0],
        registers['r10'][0]
    }

    argument_register_positions = {
        registers['r2'][0]: 0,
        registers['r3'][0]: 1,
        registers['r4'][0]: 2,
        registers['r5'][0]: 3,
        registers['r6'][0]: 4,
        registers['r7'][0]: 5,
        registers['r8'][0]: 6,
        registers['r9'][0]: 7,
        registers['r10'][0]: 8,
        # fp registers
        registers['f1'][0]: 0,
        registers['f2'][0]: 1,
        registers['f3'][0]: 2,
        registers['f4'][0]: 3,
        registers['f5'][0]: 4,
        registers['f6'][0]: 5,
        registers['f7'][0]: 6,
        registers['f8'][0]: 7,
        registers['f9'][0]: 8,
        registers['f10'][0]: 9,
        registers['f11'][0]: 10,
        registers['f12'][0]: 11,
        registers['f13'][0]: 12,

    }

    got_section_name = '.plt'
    ld_linux_name = 'ld64.so.1'
    elf_tls = TLSArchInfo(1, 92, [], [84], [], 0x7000, 0x8000)


register_arch([r'sparc|sparc64|sparcv9|em_sparcv9'], 64, 'Iend_BE', ArchSPARC64)