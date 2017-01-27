

#define WIN32_LEAN_AND_MEAN
#define _CRT_SECURE_NO_WARNINGS 1
#include <windows.h>
#include <stdio.h>
#include <io.h>
#include <malloc.h>

static char *get_export_names(int fd);

/* extract the basename of a file */
static char *file_basename(const char *name)
{
	const char *p = strchr(name, 0);
	while (p > name
		&& p[-1] != '/'
		&& p[-1] != '\\'
		)
		--p;
	return (char*)p;
}

int main(int argc, char **argv)
{
	int ret, v, i;
	char infile[MAX_PATH];
	char outfile[MAX_PATH];

	static const char *ext[] = { ".dll", ".exe", NULL };
	const char *file, **pp;
	char path[MAX_PATH], *p, *q;
	FILE *fp, *op;

	infile[0] = 0;
	outfile[0] = 0;
	fp = op = NULL;
	v = 0;
	ret = 1;
	p = NULL;

	for (i = 1; i < argc; ++i) {
		const char *a = argv[i];
		if ('-' == a[0]) {
			if (0 == strcmp(a, "-v")) {
				v = 1;
			}
			else if (0 == strcmp(a, "-o")) {
				if (++i == argc)
					goto usage;
				strcpy(outfile, argv[i]);
			}
			else
				goto usage;
		}
		else if (0 == infile[0])
			strcpy(infile, a);
		else
			goto usage;
	}

	if (0 == infile[0]) {
	usage:
		fprintf(stderr,
			"Makedef: create export definition file (.def) from a dll\n"
			"Usage: Makedef library.dll [-o outputfile] [-v]\n"
		);
		goto the_end;
	}

	if (0 == outfile[0])
	{
		strcpy(outfile, file_basename(infile));
		q = strrchr(outfile, '.');
		if (NULL == q)
			q = strchr(outfile, 0);
		strcpy(q, ".def");
	}

	file = infile;

#ifdef _WIN32
	pp = ext;
	do if (SearchPath(NULL, file, *pp, sizeof path, path, NULL)) {
		file = path;
		break;
	} while (*pp++);
#endif

	fp = fopen(file, "rb");
	if (NULL == fp) {
		fprintf(stderr, "Makedef: no such file: %s\n", infile);
		goto the_end;
	}
	if (v)
		printf("--> %s\n", file);

	p = get_export_names(_fileno(fp));
	if (NULL == p) {
		fprintf(stderr, "Makedef: could not get exported function names.\n");
		goto the_end;
	}

	op = fopen(outfile, "w");
	if (NULL == op) {
		fprintf(stderr, "Makedef: could not create output file: %s\n", outfile);
		goto the_end;
	}

	fprintf(op, "LIBRARY %s\n\nEXPORTS\n", file_basename(file));
	for (q = p, i = 0; *q; ++i) {
		fprintf(op, "%s\n", q);
		q += strlen(q) + 1;
	}

	if (v) {
		printf("<-- %s\n", outfile);
		printf("%d symbol(s) found\n\n", i);
		for (q = p, i = 0; *q; ++i) {
			printf("%s\n", q);
			q += strlen(q) + 1;
		}
	}

	ret = 0;

the_end:
	if (p)
		free(p);
	if (fp)
		fclose(fp);
	if (op)
		fclose(op);
	return ret;
}

int read_mem(int fd, unsigned offset, void *buffer, unsigned len)
{
	_lseek(fd, offset, SEEK_SET);
	return len == _read(fd, buffer, len);
}

/* -------------------------------------------------------------- */

#if defined _M_X64 || defined __amd64
# define IMAGE_FILE_MACHINE 0x8664
#elif defined _M_IX86 || defined __i386__
# define IMAGE_FILE_MACHINE 0x014C
#endif

/* -------------------------------------------------------------- */

static char *get_export_names(int fd)
{
	int l, i, n, n0;
	char *p;

	IMAGE_SECTION_HEADER ish;
	IMAGE_EXPORT_DIRECTORY ied;
	IMAGE_DOS_HEADER dh;
	IMAGE_FILE_HEADER ih;
	DWORD sig, ref, addr, ptr, namep;
#ifdef TCC_TARGET_X86_64
	IMAGE_OPTIONAL_HEADER64 oh;
#else
	IMAGE_OPTIONAL_HEADER32 oh;
#endif
	int pef_hdroffset, opt_hdroffset, sec_hdroffset;

	n = n0 = 0;
	p = NULL;

	if (!read_mem(fd, 0, &dh, sizeof dh))
		goto the_end;
	if (!read_mem(fd, dh.e_lfanew, &sig, sizeof sig))
		goto the_end;
	if (sig != 0x00004550)
		goto the_end;
	pef_hdroffset = dh.e_lfanew + sizeof sig;
	if (!read_mem(fd, pef_hdroffset, &ih, sizeof ih))
		goto the_end;
	if (IMAGE_FILE_MACHINE != ih.Machine)
		goto the_end;
	opt_hdroffset = pef_hdroffset + sizeof ih;
	sec_hdroffset = opt_hdroffset + sizeof oh;
	if (!read_mem(fd, opt_hdroffset, &oh, sizeof oh))
		goto the_end;

	if (IMAGE_DIRECTORY_ENTRY_EXPORT >= oh.NumberOfRvaAndSizes)
		goto the_end;

	addr = oh.DataDirectory[IMAGE_DIRECTORY_ENTRY_EXPORT].VirtualAddress;
	//printf("addr: %08x\n", addr);
	for (i = 0; i < ih.NumberOfSections; ++i) {
		if (!read_mem(fd, sec_hdroffset + i * sizeof ish, &ish, sizeof ish))
			goto the_end;
		//printf("vaddr: %08x\n", ish.VirtualAddress);
		if (addr >= ish.VirtualAddress && addr < ish.VirtualAddress + ish.SizeOfRawData)
			goto found;
	}
	goto the_end;

found:
	ref = ish.VirtualAddress - ish.PointerToRawData;
	if (!read_mem(fd, addr - ref, &ied, sizeof ied))
		goto the_end;

	namep = ied.AddressOfNames - ref;
	for (i = 0; i != ied.NumberOfNames; ++i) {
		if (!read_mem(fd, namep, &ptr, sizeof ptr))
			goto the_end;
		namep += sizeof ptr;
		for (l = 0;;) {
			if (n + 1 >= n0)
				p = realloc(p, n0 = n0 ? n0 * 2 : 256);
			if (!read_mem(fd, ptr - ref + l++, p + n, 1)) {
				free(p), p = NULL;
				goto the_end;
			}
			if (p[n++] == 0)
				break;
		}
	}
	if (p)
		p[n] = 0;
the_end:
	return p;
}

/* -------------------------------------------------------------- */
