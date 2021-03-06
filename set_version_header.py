#!python -u

import os, sys
import datetime
import re
import glob
import tarfile
import subprocess
import shutil
import time

def next_build_number():
    try:
        file = open('.build_number', 'r')
        build_number = file.read()
        file.close()
    except IOError:
        build_number = '0'

    file = open('.build_number', 'w')
    file.write(str(int(build_number) + 1))
    file.close()

    return build_number


def make_header():
    now = datetime.datetime.now()

    file = open('include\\version.h', 'w')

    file.write('#define VENDOR_NAME_STR\t\t"' + os.environ['VENDOR_NAME'] + '"\n')
    file.write('#define VENDOR_PREFIX_STR\t"' + os.environ['VENDOR_PREFIX'] + '"\n')

    if 'VENDOR_DEVICE_ID' in os.environ.keys():
        file.write('#define VENDOR_DEVICE_ID_STR\t"' + os.environ['VENDOR_DEVICE_ID'] + '"\n')

    file.write('#define PRODUCT_NAME_STR\t"' + os.environ['PRODUCT_NAME'] + '"\n')
    file.write('\n')

    file.write('#define MAJOR_VERSION\t\t' + os.environ['MAJOR_VERSION'] + '\n')
    file.write('#define MAJOR_VERSION_STR\t"' + os.environ['MAJOR_VERSION'] + '"\n')
    file.write('\n')

    file.write('#define MINOR_VERSION\t\t' + os.environ['MINOR_VERSION'] + '\n')
    file.write('#define MINOR_VERSION_STR\t"' + os.environ['MINOR_VERSION'] + '"\n')
    file.write('\n')

    file.write('#define MICRO_VERSION\t\t' + os.environ['MICRO_VERSION'] + '\n')
    file.write('#define MICRO_VERSION_STR\t"' + os.environ['MICRO_VERSION'] + '"\n')
    file.write('\n')

    file.write('#define BUILD_NUMBER\t\t' + os.environ['BUILD_NUMBER'] + '\n')
    file.write('#define BUILD_NUMBER_STR\t"' + os.environ['BUILD_NUMBER'] + '"\n')
    file.write('\n')

    file.write('#define YEAR\t\t\t' + str(now.year) + '\n')
    file.write('#define YEAR_STR\t\t"' + str(now.year) + '"\n')
    file.write('\n')

    file.write('#define MONTH\t\t\t' + str(now.month) + '\n')
    file.write('#define MONTH_STR\t\t"' + str(now.month) + '"\n')
    file.write('\n')

    file.write('#define DAY\t\t\t' + str(now.day) + '\n')
    file.write('#define DAY_STR\t\t\t"' + str(now.day) + '"\n')
    file.write('\n')

    file.close()


def copy_inf(vs, name):
    src = open('src\\%s.inf' % name, 'r')
    dst = open('%s\\%s.inf' % (vs, name), 'w')

    for line in src:
        line = re.sub('@MAJOR_VERSION@', os.environ['MAJOR_VERSION'], line)
        line = re.sub('@MINOR_VERSION@', os.environ['MINOR_VERSION'], line)
        line = re.sub('@MICRO_VERSION@', os.environ['MICRO_VERSION'], line)
        line = re.sub('@BUILD_NUMBER@', os.environ['BUILD_NUMBER'], line)
        line = re.sub('@VENDOR_NAME@', os.environ['VENDOR_NAME'], line)
        line = re.sub('@VENDOR_PREFIX@', os.environ['VENDOR_PREFIX'], line)
        line = re.sub('@PRODUCT_NAME@', os.environ['PRODUCT_NAME'], line)

        if re.search('@VENDOR_DEVICE_ID@', line):
            if 'VENDOR_DEVICE_ID' not in os.environ.keys():
                continue
            line = re.sub('@VENDOR_DEVICE_ID@', os.environ['VENDOR_DEVICE_ID'], line)

        dst.write(line)

    dst.close()
    src.close()

if __name__ == '__main__':
    driver = 'xenusbdevice'

    if 'VENDOR_NAME' not in os.environ.keys():
        os.environ['VENDOR_NAME'] = 'Xen Project'

    if 'VENDOR_PREFIX' not in os.environ.keys():
        os.environ['VENDOR_PREFIX'] = 'XP'

    if 'PRODUCT_NAME' not in os.environ.keys():
        os.environ['PRODUCT_NAME'] = 'Xen'

    if 'MAJOR_VERSION' not in os.environ.keys():
        os.environ['MAJOR_VERSION'] = '1'

    if 'MINOR_VERSION' not in os.environ.keys():
        os.environ['MINOR_VERSION'] = '0'

    if 'MICRO_VERSION' not in os.environ.keys():
        os.environ['MICRO_VERSION'] = '0'

    if 'BUILD_NUMBER' not in os.environ.keys():
        os.environ['BUILD_NUMBER'] = next_build_number()

    if 'GIT_REVISION' in os.environ.keys():
        revision = open('revision', 'w')
        print(os.environ['GIT_REVISION'], file=revision)
        revision.close()

    print("VENDOR_NAME\t\t'%s'" % os.environ['VENDOR_NAME'])
    print("VENDOR_PREFIX\t\t'%s'" % os.environ['VENDOR_PREFIX'])

    if 'VENDOR_DEVICE_ID' in os.environ.keys():
        print("VENDOR_DEVICE_ID\t'%s'" % os.environ['VENDOR_DEVICE_ID'])

    print("PRODUCT_NAME\t\t'%s'" % os.environ['PRODUCT_NAME'])
    print("MAJOR_VERSION\t\t%s" % os.environ['MAJOR_VERSION'])
    print("MINOR_VERSION\t\t%s" % os.environ['MINOR_VERSION'])
    print("MICRO_VERSION\t\t%s" % os.environ['MICRO_VERSION'])
    print("BUILD_NUMBER\t\t%s" % os.environ['BUILD_NUMBER'])
    print()

    make_header()
    copy_inf('vs2017', driver)
