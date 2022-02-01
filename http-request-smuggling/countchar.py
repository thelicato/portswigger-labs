def count_char():
    with open('request.txt', 'r') as f:
        lines = f.readlines()
        fixed_lines = [l.replace('\n', '\r\n').replace('\r\r','\r') for l in lines]
        chars_num = sum([len(l) for l in fixed_lines])
        print(fixed_lines)
        print(chars_num)

if __name__ == '__main__':
    count_char()