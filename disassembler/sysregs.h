#pragma once

enum SystemReg {
	SYSREG_NONE=32769,
	REG_OSDTRRX_EL1=32770,
	REG_DBGBVR0_EL1=32772,
	REG_DBGBCR0_EL1=32773,
	REG_DBGWVR0_EL1=32774,
	REG_DBGWCR0_EL1=32775,
	REG_DBGBVR1_EL1=32780,
	REG_DBGBCR1_EL1=32781,
	REG_DBGWVR1_EL1=32782,
	REG_DBGWCR1_EL1=32783,
	REG_MDCCINT_EL1=32784,
	REG_MDSCR_EL1=32786,
	REG_DBGBVR2_EL1=32788,
	REG_DBGBCR2_EL1=32789,
	REG_DBGWVR2_EL1=32790,
	REG_DBGWCR2_EL1=32791,
	REG_OSDTRTX_EL1=32794,
	REG_DBGBVR3_EL1=32796,
	REG_DBGBCR3_EL1=32797,
	REG_DBGWVR3_EL1=32798,
	REG_DBGWCR3_EL1=32799,
	REG_DBGBVR4_EL1=32804,
	REG_DBGBCR4_EL1=32805,
	REG_DBGWVR4_EL1=32806,
	REG_DBGWCR4_EL1=32807,
	REG_DBGBVR5_EL1=32812,
	REG_DBGBCR5_EL1=32813,
	REG_DBGWVR5_EL1=32814,
	REG_DBGWCR5_EL1=32815,
	REG_OSECCR_EL1=32818,
	REG_DBGBVR6_EL1=32820,
	REG_DBGBCR6_EL1=32821,
	REG_DBGWVR6_EL1=32822,
	REG_DBGWCR6_EL1=32823,
	REG_DBGBVR7_EL1=32828,
	REG_DBGBCR7_EL1=32829,
	REG_DBGWVR7_EL1=32830,
	REG_DBGWCR7_EL1=32831,
	REG_DBGBVR8_EL1=32836,
	REG_DBGBCR8_EL1=32837,
	REG_DBGWVR8_EL1=32838,
	REG_DBGWCR8_EL1=32839,
	REG_DBGBVR9_EL1=32844,
	REG_DBGBCR9_EL1=32845,
	REG_DBGWVR9_EL1=32846,
	REG_DBGWCR9_EL1=32847,
	REG_DBGBVR10_EL1=32852,
	REG_DBGBCR10_EL1=32853,
	REG_DBGWVR10_EL1=32854,
	REG_DBGWCR10_EL1=32855,
	REG_DBGBVR11_EL1=32860,
	REG_DBGBCR11_EL1=32861,
	REG_DBGWVR11_EL1=32862,
	REG_DBGWCR11_EL1=32863,
	REG_DBGBVR12_EL1=32868,
	REG_DBGBCR12_EL1=32869,
	REG_DBGWVR12_EL1=32870,
	REG_DBGWCR12_EL1=32871,
	REG_DBGBVR13_EL1=32876,
	REG_DBGBCR13_EL1=32877,
	REG_DBGWVR13_EL1=32878,
	REG_DBGWCR13_EL1=32879,
	REG_DBGBVR14_EL1=32884,
	REG_DBGBCR14_EL1=32885,
	REG_DBGWVR14_EL1=32886,
	REG_DBGWCR14_EL1=32887,
	REG_DBGBVR15_EL1=32892,
	REG_DBGBCR15_EL1=32893,
	REG_DBGWVR15_EL1=32894,
	REG_DBGWCR15_EL1=32895,
	REG_OSLAR_EL1=32900,
	REG_OSDLR_EL1=32924,
	REG_DBGPRCR_EL1=32932,
	REG_DBGCLAIMSET_EL1=33734,
	REG_DBGCLAIMCLR_EL1=33742,
	REG_TRCTRACEIDR=34817,
	REG_TRCVICTLR=34818,
	REG_TRCSEQEVR0=34820,
	REG_TRCCNTRLDVR0=34821,
	REG_TRCIMSPEC0=34823,
	REG_TRCPRGCTLR=34824,
	REG_TRCQCTLR=34825,
	REG_TRCVIIECTLR=34826,
	REG_TRCSEQEVR1=34828,
	REG_TRCCNTRLDVR1=34829,
	REG_TRCIMSPEC1=34831,
	REG_TRCPROCSELR=34832,
	REG_TRCVISSCTLR=34834,
	REG_TRCSEQEVR2=34836,
	REG_TRCCNTRLDVR2=34837,
	REG_TRCIMSPEC2=34839,
	REG_TRCVIPCSSCTLR=34842,
	REG_TRCCNTRLDVR3=34845,
	REG_TRCIMSPEC3=34847,
	REG_TRCCONFIGR=34848,
	REG_TRCCNTCTLR0=34853,
	REG_TRCIMSPEC4=34855,
	REG_TRCCNTCTLR1=34861,
	REG_TRCIMSPEC5=34863,
	REG_TRCAUXCTLR=34864,
	REG_TRCSEQRSTEVR=34868,
	REG_TRCCNTCTLR2=34869,
	REG_TRCIMSPEC6=34871,
	REG_TRCSEQSTR=34876,
	REG_TRCCNTCTLR3=34877,
	REG_TRCIMSPEC7=34879,
	REG_TRCEVENTCTL0R=34880,
	REG_TRCVDCTLR=34882,
	REG_TRCEXTINSELR=34884,
	REG_TRCCNTVR0=34885,
	REG_TRCEVENTCTL1R=34888,
	REG_TRCVDSACCTLR=34890,
	REG_TRCEXTINSELR1=34892,
	REG_TRCCNTVR1=34893,
	REG_TRCRSR=34896,
	REG_TRCVDARCCTLR=34898,
	REG_TRCEXTINSELR2=34900,
	REG_TRCCNTVR2=34901,
	REG_TRCSTALLCTLR=34904,
	REG_TRCEXTINSELR3=34908,
	REG_TRCCNTVR3=34909,
	REG_TRCTSCTLR=34912,
	REG_TRCSYNCPR=34920,
	REG_TRCCCCTLR=34928,
	REG_TRCBBCTLR=34936,
	REG_TRCRSCTLR16=34945,
	REG_TRCSSCCR0=34946,
	REG_TRCSSPCICR0=34947,
	REG_TRCOSLAR=34948,
	REG_TRCRSCTLR17=34953,
	REG_TRCSSCCR1=34954,
	REG_TRCSSPCICR1=34955,
	REG_TRCRSCTLR2=34960,
	REG_TRCRSCTLR18=34961,
	REG_TRCSSCCR2=34962,
	REG_TRCSSPCICR2=34963,
	REG_TRCRSCTLR3=34968,
	REG_TRCRSCTLR19=34969,
	REG_TRCSSCCR3=34970,
	REG_TRCSSPCICR3=34971,
	REG_TRCRSCTLR4=34976,
	REG_TRCRSCTLR20=34977,
	REG_TRCSSCCR4=34978,
	REG_TRCSSPCICR4=34979,
	REG_TRCPDCR=34980,
	REG_TRCRSCTLR5=34984,
	REG_TRCRSCTLR21=34985,
	REG_TRCSSCCR5=34986,
	REG_TRCSSPCICR5=34987,
	REG_TRCRSCTLR6=34992,
	REG_TRCRSCTLR22=34993,
	REG_TRCSSCCR6=34994,
	REG_TRCSSPCICR6=34995,
	REG_TRCRSCTLR7=35000,
	REG_TRCRSCTLR23=35001,
	REG_TRCSSCCR7=35002,
	REG_TRCSSPCICR7=35003,
	REG_TRCRSCTLR8=35008,
	REG_TRCRSCTLR24=35009,
	REG_TRCSSCSR0=35010,
	REG_TRCRSCTLR9=35016,
	REG_TRCRSCTLR25=35017,
	REG_TRCSSCSR1=35018,
	REG_TRCRSCTLR10=35024,
	REG_TRCRSCTLR26=35025,
	REG_TRCSSCSR2=35026,
	REG_TRCRSCTLR11=35032,
	REG_TRCRSCTLR27=35033,
	REG_TRCSSCSR3=35034,
	REG_TRCRSCTLR12=35040,
	REG_TRCRSCTLR28=35041,
	REG_TRCSSCSR4=35042,
	REG_TRCRSCTLR13=35048,
	REG_TRCRSCTLR29=35049,
	REG_TRCSSCSR5=35050,
	REG_TRCRSCTLR14=35056,
	REG_TRCRSCTLR30=35057,
	REG_TRCSSCSR6=35058,
	REG_TRCRSCTLR15=35064,
	REG_TRCRSCTLR31=35065,
	REG_TRCSSCSR7=35066,
	REG_TRCACVR0=35072,
	REG_TRCACVR8=35073,
	REG_TRCACATR0=35074,
	REG_TRCACATR8=35075,
	REG_TRCDVCVR0=35076,
	REG_TRCDVCVR4=35077,
	REG_TRCDVCMR0=35078,
	REG_TRCDVCMR4=35079,
	REG_TRCACVR1=35088,
	REG_TRCACVR9=35089,
	REG_TRCACATR1=35090,
	REG_TRCACATR9=35091,
	REG_TRCACVR2=35104,
	REG_TRCACVR10=35105,
	REG_TRCACATR2=35106,
	REG_TRCACATR10=35107,
	REG_TRCDVCVR1=35108,
	REG_TRCDVCVR5=35109,
	REG_TRCDVCMR1=35110,
	REG_TRCDVCMR5=35111,
	REG_TRCACVR3=35120,
	REG_TRCACVR11=35121,
	REG_TRCACATR3=35122,
	REG_TRCACATR11=35123,
	REG_TRCACVR4=35136,
	REG_TRCACVR12=35137,
	REG_TRCACATR4=35138,
	REG_TRCACATR12=35139,
	REG_TRCDVCVR2=35140,
	REG_TRCDVCVR6=35141,
	REG_TRCDVCMR2=35142,
	REG_TRCDVCMR6=35143,
	REG_TRCACVR5=35152,
	REG_TRCACVR13=35153,
	REG_TRCACATR5=35154,
	REG_TRCACATR13=35155,
	REG_TRCACVR6=35168,
	REG_TRCACVR14=35169,
	REG_TRCACATR6=35170,
	REG_TRCACATR14=35171,
	REG_TRCDVCVR3=35172,
	REG_TRCDVCVR7=35173,
	REG_TRCDVCMR3=35174,
	REG_TRCDVCMR7=35175,
	REG_TRCACVR7=35184,
	REG_TRCACVR15=35185,
	REG_TRCACATR7=35186,
	REG_TRCACATR15=35187,
	REG_TRCCIDCVR0=35200,
	REG_TRCVMIDCVR0=35201,
	REG_TRCCIDCCTLR0=35202,
	REG_TRCCIDCCTLR1=35210,
	REG_TRCCIDCVR1=35216,
	REG_TRCVMIDCVR1=35217,
	REG_TRCVMIDCCTLR0=35218,
	REG_TRCVMIDCCTLR1=35226,
	REG_TRCCIDCVR2=35232,
	REG_TRCVMIDCVR2=35233,
	REG_TRCCIDCVR3=35248,
	REG_TRCVMIDCVR3=35249,
	REG_TRCCIDCVR4=35264,
	REG_TRCVMIDCVR4=35265,
	REG_TRCCIDCVR5=35280,
	REG_TRCVMIDCVR5=35281,
	REG_TRCCIDCVR6=35296,
	REG_TRCVMIDCVR6=35297,
	REG_TRCCIDCVR7=35312,
	REG_TRCVMIDCVR7=35313,
	REG_TRCITCTRL=35716,
	REG_TRCCLAIMSET=35782,
	REG_TRCCLAIMCLR=35790,
	REG_TRCLAR=35814,
	REG_TEECR32_EL1=36864,
	REG_TEEHBR32_EL1=36992,
	REG_DBGDTR_EL0=38944,
	REG_DBGDTRTX_EL0=38952,
	REG_DBGVCR32_EL2=41016,
	REG_SCTLR_EL1=49280,
	REG_ACTLR_EL1=49281,
	REG_CPACR_EL1=49282,
	REG_RGSR_EL1=49285,
	REG_GCR_EL1=49286,
	REG_TRFCR_EL1=49297,
	REG_TTBR0_EL1=49408,
	REG_TTBR1_EL1=49409,
	REG_TCR_EL1=49410,
	REG_APIAKEYLO_EL1=49416,
	REG_APIAKEYHI_EL1=49417,
	REG_APIBKEYLO_EL1=49418,
	REG_APIBKEYHI_EL1=49419,
	REG_APDAKEYLO_EL1=49424,
	REG_APDAKEYHI_EL1=49425,
	REG_APDBKEYLO_EL1=49426,
	REG_APDBKEYHI_EL1=49427,
	REG_APGAKEYLO_EL1=49432,
	REG_APGAKEYHI_EL1=49433,
	REG_SPSR_EL1=49664,
	REG_ELR_EL1=49665,
	REG_SP_EL0=49672,
	REG_SPSEL=49680,
	REG_CURRENTEL=49682,
	REG_PAN=49683,
	REG_UAO=49684,
	REG_ICC_PMR_EL1=49712,
	REG_AFSR0_EL1=49800,
	REG_AFSR1_EL1=49801,
	REG_ESR_EL1=49808,
	REG_ERRSELR_EL1=49817,
	REG_ERXCTLR_EL1=49825,
	REG_ERXSTATUS_EL1=49826,
	REG_ERXADDR_EL1=49827,
	REG_ERXPFGCTL_EL1=49829,
	REG_ERXPFGCDN_EL1=49830,
	REG_ERXMISC0_EL1=49832,
	REG_ERXMISC1_EL1=49833,
	REG_ERXMISC2_EL1=49834,
	REG_ERXMISC3_EL1=49835,
	REG_ERXTS_EL1=49839,
	REG_TFSR_EL1=49840,
	REG_TFSRE0_EL1=49841,
	REG_FAR_EL1=49920,
	REG_PAR_EL1=50080,
	REG_PMSCR_EL1=50376,
	REG_PMSICR_EL1=50378,
	REG_PMSIRR_EL1=50379,
	REG_PMSFCR_EL1=50380,
	REG_PMSEVFR_EL1=50381,
	REG_PMSLATFR_EL1=50382,
	REG_PMSIDR_EL1=50383,
	REG_PMBLIMITR_EL1=50384,
	REG_PMBPTR_EL1=50385,
	REG_PMBSR_EL1=50387,
	REG_PMBIDR_EL1=50391,
	REG_TRBLIMITR_EL1=50392,
	REG_TRBPTR_EL1=50393,
	REG_TRBBASER_EL1=50394,
	REG_TRBSR_EL1=50395,
	REG_TRBMAR_EL1=50396,
	REG_TRBTRG_EL1=50398,
	REG_PMINTENSET_EL1=50417,
	REG_PMINTENCLR_EL1=50418,
	REG_PMMIR_EL1=50422,
	REG_MAIR_EL1=50448,
	REG_AMAIR_EL1=50456,
	REG_LORSA_EL1=50464,
	REG_LOREA_EL1=50465,
	REG_LORN_EL1=50466,
	REG_LORC_EL1=50467,
	REG_MPAM1_EL1=50472,
	REG_MPAM0_EL1=50473,
	REG_VBAR_EL1=50688,
	REG_RMR_EL1=50690,
	REG_DISR_EL1=50697,
	REG_ICC_EOIR0_EL1=50753,
	REG_ICC_BPR0_EL1=50755,
	REG_ICC_AP0R0_EL1=50756,
	REG_ICC_AP0R1_EL1=50757,
	REG_ICC_AP0R2_EL1=50758,
	REG_ICC_AP0R3_EL1=50759,
	REG_ICC_AP1R0_EL1=50760,
	REG_ICC_AP1R1_EL1=50761,
	REG_ICC_AP1R2_EL1=50762,
	REG_ICC_AP1R3_EL1=50763,
	REG_ICC_DIR_EL1=50777,
	REG_ICC_SGI1R_EL1=50781,
	REG_ICC_ASGI1R_EL1=50782,
	REG_ICC_SGI0R_EL1=50783,
	REG_ICC_EOIR1_EL1=50785,
	REG_ICC_BPR1_EL1=50787,
	REG_ICC_CTLR_EL1=50788,
	REG_ICC_SRE_EL1=50789,
	REG_ICC_IGRPEN0_EL1=50790,
	REG_ICC_IGRPEN1_EL1=50791,
	REG_ICC_SEIEN_EL1=50792,
	REG_CONTEXTIDR_EL1=50817,
	REG_TPIDR_EL1=50820,
	REG_SCXTNUM_EL1=50823,
	REG_CNTKCTL_EL1=50952,
	REG_CSSELR_EL1=53248,
	REG_NZCV=55824,
	REG_DAIFSET=55825,
	REG_DIT=55829,
	REG_SSBS=55830,
	REG_TCO=55831,
	REG_FPCR=55840,
	REG_FPSR=55841,
	REG_DSPSR_EL0=55848,
	REG_DLR_EL0=55849,
	REG_PMCR_EL0=56544,
	REG_PMCNTENSET_EL0=56545,
	REG_PMCNTENCLR_EL0=56546,
	REG_PMOVSCLR_EL0=56547,
	REG_PMSWINC_EL0=56548,
	REG_PMSELR_EL0=56549,
	REG_PMCCNTR_EL0=56552,
	REG_PMXEVTYPER_EL0=56553,
	REG_PMXEVCNTR_EL0=56554,
	REG_DAIFCLR=56557,
	REG_PMUSERENR_EL0=56560,
	REG_PMOVSSET_EL0=56563,
	REG_TPIDR_EL0=56962,
	REG_TPIDRRO_EL0=56963,
	REG_SCXTNUM_EL0=56967,
	REG_AMCR_EL0=56976,
	REG_AMUSERENR_EL0=56979,
	REG_AMCNTENCLR0_EL0=56980,
	REG_AMCNTENSET0_EL0=56981,
	REG_AMCNTENCLR1_EL0=56984,
	REG_AMCNTENSET1_EL0=56985,
	REG_AMEVCNTR00_EL0=56992,
	REG_AMEVCNTR01_EL0=56993,
	REG_AMEVCNTR02_EL0=56994,
	REG_AMEVCNTR03_EL0=56995,
	REG_AMEVCNTR10_EL0=57056,
	REG_AMEVCNTR11_EL0=57057,
	REG_AMEVCNTR12_EL0=57058,
	REG_AMEVCNTR13_EL0=57059,
	REG_AMEVCNTR14_EL0=57060,
	REG_AMEVCNTR15_EL0=57061,
	REG_AMEVCNTR16_EL0=57062,
	REG_AMEVCNTR17_EL0=57063,
	REG_AMEVCNTR18_EL0=57064,
	REG_AMEVCNTR19_EL0=57065,
	REG_AMEVCNTR110_EL0=57066,
	REG_AMEVCNTR111_EL0=57067,
	REG_AMEVCNTR112_EL0=57068,
	REG_AMEVCNTR113_EL0=57069,
	REG_AMEVCNTR114_EL0=57070,
	REG_AMEVCNTR115_EL0=57071,
	REG_AMEVTYPER10_EL0=57072,
	REG_AMEVTYPER11_EL0=57073,
	REG_AMEVTYPER12_EL0=57074,
	REG_AMEVTYPER13_EL0=57075,
	REG_AMEVTYPER14_EL0=57076,
	REG_AMEVTYPER15_EL0=57077,
	REG_AMEVTYPER16_EL0=57078,
	REG_AMEVTYPER17_EL0=57079,
	REG_AMEVTYPER18_EL0=57080,
	REG_AMEVTYPER19_EL0=57081,
	REG_AMEVTYPER110_EL0=57082,
	REG_AMEVTYPER111_EL0=57083,
	REG_AMEVTYPER112_EL0=57084,
	REG_AMEVTYPER113_EL0=57085,
	REG_AMEVTYPER114_EL0=57086,
	REG_AMEVTYPER115_EL0=57087,
	REG_CNTFRQ_EL0=57088,
	REG_CNTP_TVAL_EL0=57104,
	REG_CNTP_CTL_EL0=57105,
	REG_CNTP_CVAL_EL0=57106,
	REG_CNTV_TVAL_EL0=57112,
	REG_CNTV_CTL_EL0=57113,
	REG_CNTV_CVAL_EL0=57114,
	REG_PMEVCNTR0_EL0=57152,
	REG_PMEVCNTR1_EL0=57153,
	REG_PMEVCNTR2_EL0=57154,
	REG_PMEVCNTR3_EL0=57155,
	REG_PMEVCNTR4_EL0=57156,
	REG_PMEVCNTR5_EL0=57157,
	REG_PMEVCNTR6_EL0=57158,
	REG_PMEVCNTR7_EL0=57159,
	REG_PMEVCNTR8_EL0=57160,
	REG_PMEVCNTR9_EL0=57161,
	REG_PMEVCNTR10_EL0=57162,
	REG_PMEVCNTR11_EL0=57163,
	REG_PMEVCNTR12_EL0=57164,
	REG_PMEVCNTR13_EL0=57165,
	REG_PMEVCNTR14_EL0=57166,
	REG_PMEVCNTR15_EL0=57167,
	REG_PMEVCNTR16_EL0=57168,
	REG_PMEVCNTR17_EL0=57169,
	REG_PMEVCNTR18_EL0=57170,
	REG_PMEVCNTR19_EL0=57171,
	REG_PMEVCNTR20_EL0=57172,
	REG_PMEVCNTR21_EL0=57173,
	REG_PMEVCNTR22_EL0=57174,
	REG_PMEVCNTR23_EL0=57175,
	REG_PMEVCNTR24_EL0=57176,
	REG_PMEVCNTR25_EL0=57177,
	REG_PMEVCNTR26_EL0=57178,
	REG_PMEVCNTR27_EL0=57179,
	REG_PMEVCNTR28_EL0=57180,
	REG_PMEVCNTR29_EL0=57181,
	REG_PMEVCNTR30_EL0=57182,
	REG_PMEVTYPER0_EL0=57184,
	REG_PMEVTYPER1_EL0=57185,
	REG_PMEVTYPER2_EL0=57186,
	REG_PMEVTYPER3_EL0=57187,
	REG_PMEVTYPER4_EL0=57188,
	REG_PMEVTYPER5_EL0=57189,
	REG_PMEVTYPER6_EL0=57190,
	REG_PMEVTYPER7_EL0=57191,
	REG_PMEVTYPER8_EL0=57192,
	REG_PMEVTYPER9_EL0=57193,
	REG_PMEVTYPER10_EL0=57194,
	REG_PMEVTYPER11_EL0=57195,
	REG_PMEVTYPER12_EL0=57196,
	REG_PMEVTYPER13_EL0=57197,
	REG_PMEVTYPER14_EL0=57198,
	REG_PMEVTYPER15_EL0=57199,
	REG_PMEVTYPER16_EL0=57200,
	REG_PMEVTYPER17_EL0=57201,
	REG_PMEVTYPER18_EL0=57202,
	REG_PMEVTYPER19_EL0=57203,
	REG_PMEVTYPER20_EL0=57204,
	REG_PMEVTYPER21_EL0=57205,
	REG_PMEVTYPER22_EL0=57206,
	REG_PMEVTYPER23_EL0=57207,
	REG_PMEVTYPER24_EL0=57208,
	REG_PMEVTYPER25_EL0=57209,
	REG_PMEVTYPER26_EL0=57210,
	REG_PMEVTYPER27_EL0=57211,
	REG_PMEVTYPER28_EL0=57212,
	REG_PMEVTYPER29_EL0=57213,
	REG_PMEVTYPER30_EL0=57214,
	REG_PMCCFILTR_EL0=57215,
	REG_VPIDR_EL2=57344,
	REG_VMPIDR_EL2=57349,
	REG_SCTLR_EL2=57472,
	REG_ACTLR_EL2=57473,
	REG_HCR_EL2=57480,
	REG_MDCR_EL2=57481,
	REG_CPTR_EL2=57482,
	REG_HSTR_EL2=57483,
	REG_HACR_EL2=57487,
	REG_TRFCR_EL2=57489,
	REG_SDER32_EL2=57497,
	REG_TTBR0_EL2=57600,
	REG_TTBR1_EL2=57601,
	REG_TCR_EL2=57602,
	REG_VTTBR_EL2=57608,
	REG_VTCR_EL2=57610,
	REG_VNCR_EL2=57616,
	REG_VSTTBR_EL2=57648,
	REG_VSTCR_EL2=57650,
	REG_DACR32_EL2=57728,
	REG_SPSR_EL2=57856,
	REG_ELR_EL2=57857,
	REG_SP_EL1=57864,
	REG_SPSR_IRQ=57880,
	REG_SPSR_ABT=57881,
	REG_SPSR_UND=57882,
	REG_SPSR_FIQ=57883,
	REG_IFSR32_EL2=57985,
	REG_AFSR0_EL2=57992,
	REG_AFSR1_EL2=57993,
	REG_ESR_EL2=58000,
	REG_VSESR_EL2=58003,
	REG_FPEXC32_EL2=58008,
	REG_TFSR_EL2=58032,
	REG_FAR_EL2=58112,
	REG_HPFAR_EL2=58116,
	REG_PMSCR_EL2=58568,
	REG_MAIR_EL2=58640,
	REG_AMAIR_EL2=58648,
	REG_MPAMHCR_EL2=58656,
	REG_MPAMVPMV_EL2=58657,
	REG_MPAM2_EL2=58664,
	REG_MPAMVPM0_EL2=58672,
	REG_MPAMVPM1_EL2=58673,
	REG_MPAMVPM2_EL2=58674,
	REG_MPAMVPM3_EL2=58675,
	REG_MPAMVPM4_EL2=58676,
	REG_MPAMVPM5_EL2=58677,
	REG_MPAMVPM6_EL2=58678,
	REG_MPAMVPM7_EL2=58679,
	REG_VBAR_EL2=58880,
	REG_RMR_EL2=58882,
	REG_VDISR_EL2=58889,
	REG_ICH_AP0R0_EL2=58944,
	REG_ICH_AP0R1_EL2=58945,
	REG_ICH_AP0R2_EL2=58946,
	REG_ICH_AP0R3_EL2=58947,
	REG_ICH_AP1R0_EL2=58952,
	REG_ICH_AP1R1_EL2=58953,
	REG_ICH_AP1R2_EL2=58954,
	REG_ICH_AP1R3_EL2=58955,
	REG_ICH_VSEIR_EL2=58956,
	REG_ICC_SRE_EL2=58957,
	REG_ICH_HCR_EL2=58968,
	REG_ICH_MISR_EL2=58970,
	REG_ICH_VMCR_EL2=58975,
	REG_ICH_LR0_EL2=58976,
	REG_ICH_LR1_EL2=58977,
	REG_ICH_LR2_EL2=58978,
	REG_ICH_LR3_EL2=58979,
	REG_ICH_LR4_EL2=58980,
	REG_ICH_LR5_EL2=58981,
	REG_ICH_LR6_EL2=58982,
	REG_ICH_LR7_EL2=58983,
	REG_ICH_LR8_EL2=58984,
	REG_ICH_LR9_EL2=58985,
	REG_ICH_LR10_EL2=58986,
	REG_ICH_LR11_EL2=58987,
	REG_ICH_LR12_EL2=58988,
	REG_ICH_LR13_EL2=58989,
	REG_ICH_LR14_EL2=58990,
	REG_ICH_LR15_EL2=58991,
	REG_CONTEXTIDR_EL2=59009,
	REG_TPIDR_EL2=59010,
	REG_SCXTNUM_EL2=59015,
	REG_CNTVOFF_EL2=59139,
	REG_CNTHCTL_EL2=59144,
	REG_CNTHP_TVAL_EL2=59152,
	REG_CNTHP_CTL_EL2=59153,
	REG_CNTHP_CVAL_EL2=59154,
	REG_CNTHV_TVAL_EL2=59160,
	REG_CNTHV_CTL_EL2=59161,
	REG_CNTHV_CVAL_EL2=59162,
	REG_CNTHVS_TVAL_EL2=59168,
	REG_CNTHVS_CTL_EL2=59169,
	REG_CNTHVS_CVAL_EL2=59170,
	REG_CNTHPS_TVAL_EL2=59176,
	REG_CNTHPS_CTL_EL2=59177,
	REG_CNTHPS_CVAL_EL2=59178,
	REG_SCTLR_EL12=59520,
	REG_CPACR_EL12=59522,
	REG_TRFCR_EL12=59537,
	REG_TTBR0_EL12=59648,
	REG_TTBR1_EL12=59649,
	REG_TCR_EL12=59650,
	REG_SPSR_EL12=59904,
	REG_ELR_EL12=59905,
	REG_AFSR0_EL12=60040,
	REG_AFSR1_EL12=60041,
	REG_ESR_EL12=60048,
	REG_TFSR_EL12=60080,
	REG_FAR_EL12=60160,
	REG_PMSCR_EL12=60616,
	REG_MAIR_EL12=60688,
	REG_AMAIR_EL12=60696,
	REG_MPAM1_EL12=60712,
	REG_VBAR_EL12=60928,
	REG_CONTEXTIDR_EL12=61057,
	REG_SCXTNUM_EL12=61063,
	REG_CNTKCTL_EL12=61192,
	REG_CNTP_TVAL_EL02=61200,
	REG_CNTP_CTL_EL02=61201,
	REG_CNTP_CVAL_EL02=61202,
	REG_CNTV_TVAL_EL02=61208,
	REG_CNTV_CTL_EL02=61209,
	REG_CNTV_CVAL_EL02=61210,
	REG_SCTLR_EL3=61568,
	REG_ACTLR_EL3=61569,
	REG_SCR_EL3=61576,
	REG_SDER32_EL3=61577,
	REG_CPTR_EL3=61578,
	REG_MDCR_EL3=61593,
	REG_TTBR0_EL3=61696,
	REG_TCR_EL3=61698,
	REG_SPSR_EL3=61952,
	REG_ELR_EL3=61953,
	REG_SP_EL2=61960,
	REG_AFSR0_EL3=62088,
	REG_AFSR1_EL3=62089,
	REG_ESR_EL3=62096,
	REG_TFSR_EL3=62128,
	REG_FAR_EL3=62208,
	REG_MAIR_EL3=62736,
	REG_AMAIR_EL3=62744,
	REG_MPAM3_EL3=62760,
	REG_VBAR_EL3=62976,
	REG_RMR_EL3=62978,
	REG_ICC_CTLR_EL3=63076,
	REG_ICC_SRE_EL3=63077,
	REG_ICC_IGRPEN1_EL3=63079,
	REG_TPIDR_EL3=63106,
	REG_SCXTNUM_EL3=63111,
	REG_CNTPS_TVAL_EL1=65296,
	REG_CNTPS_CTL_EL1=65297,
	REG_CNTPS_CVAL_EL1=65298,
	/* exceptional system registers */
	REG_PSTATE_SPSEL=65299, // (op0,op1,crn,crm,op2)=(0,0,4,9,5) doesn't map to [SYSREG_NONE+1, SYSREG_END)
	/* end marker, needed for other reg defines */
	SYSREG_END=65300,
};

#ifdef __cplusplus
extern "C" {
#endif
const char *get_system_register_name(enum SystemReg);
const char *get_system_register_name_decomposed(int op0, int op1, int CRn, int CRm, int op2);
#ifdef __cplusplus
}
#endif

