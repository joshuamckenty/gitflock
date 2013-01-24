from pycopia.SMI import SMI

MIBS_DIR = './mibs/'

mods = [x for x in os.listdir('mibs')]
SMI.load_modules(mods)