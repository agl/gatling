#define _FILE_OFFSET_BITS 64
#include <sys/ioctl.h>
#include <unistd.h>
#include <fcntl.h>
#include <stdio.h>
#include <linux/fs.h>
#include <sys/mman.h>
#include <sys/stat.h>
#include <stdlib.h>

#ifndef FIBMAP
#define FIBMAP BMAP_IOCTL
#endif

struct lookup {
  unsigned int l,p; /* logical block, physical block */
};

int compare(const void *a, const void *b) {
  register const struct lookup* A=a;
  register const struct lookup* B=b;
  return A->p-B->p;
}

static int dryrun;

volatile int x;

void touch(const char* block) {
  x=*block;
}

static unsigned long abs(long a) {
  return (a<0)?-a:a;
}

int main(int argc,char* argv[]) {
  int fd=open(argv[1],O_RDONLY);
  unsigned int block,i,blocks,chunk,chunks,cur,blocksleft,blocksdone,delta;
  unsigned long long h1,h2;
  struct stat s;
  struct lookup *lt;

  if (argc<2) {
    fprintf(stderr,"usage: defrag filename > destination\n");
    return 0;
  }
  if (fd<0) {
    perror("open");
    return 1;
  }
  if (fstat(fd,&s)) {
    perror("fstat");
    return 1;
  }
  blocks=s.st_size/s.st_blksize;
  fprintf(stderr,"%u blocks, allocating look-up table\n",blocks);
  lt=(struct lookup*)malloc(blocks*sizeof(struct lookup));
  if (!lt) {
    perror("malloc");
    return 1;
  }
  h1=h2=0;
  for (i=0; i<blocks; i++) {
    block=i;
    if (ioctl(fd,FIBMAP,&block)) {
      perror("ioctl FIBMAP");
      return 1;
    }
    if (!block) {
      fprintf(stderr,"block is zero!\n");
      return 1;
    }
    lt[i].l=i; lt[i].p=block;
    if (i) h1+=abs(lt[i].p-lt[i-1].p);
  }

  /* the next step is to sort the look-up table so that we read in
   * ascending block order.  However, we don't handle the whole table at
   * once, only 128M at a time. */

  chunks=(s.st_size+128*1024*1024-1)/(128*1024*1024); cur=0;
  fprintf(stderr,"populated look-up table, %u chunks\n",chunks);
  dryrun=isatty(1);
  blocksleft=blocks; blocksdone=0;
  for (chunk=0; chunk<chunks; ++chunk) {
    int blocksperchunk;
    unsigned long chunksize=128*1024*1024;
    char* map=0;
    if (!dryrun)
      fprintf(stderr,"chunk %u/%u [%luMB]: ",
	      chunk+1,chunks,chunksize/(1024*1024)); fflush(stderr);
    if (chunksize>blocksleft*s.st_blksize) {
      delta=blocksleft;
      chunksize=s.st_size-blocksdone*s.st_blksize;
    } else
      delta=chunksize/s.st_blksize;
    blocksleft-=delta;
    if (!dryrun) {
      map=mmap(0,chunksize,PROT_READ,MAP_SHARED,fd,blocksdone*s.st_blksize);
      if (map==(char*)-1) {
	perror("mmap");
	return 1;
      }
      madvise(map,chunksize,MADV_RANDOM); /* tell the OS not to read ahead */
    }

    /* how many blocks are in this chunk? */
    blocksperchunk=chunksize/s.st_blksize;

    qsort(lt+cur,blocksperchunk,sizeof(struct lookup),compare);
    for (i=0; i<blocksperchunk; ++i) {
      if (!dryrun && !(i%100)) {
	int j;
	fprintf(stderr,"\rchunk %u/%u [%luMB]: reading block %u/%u...     ",
		chunk+1,chunks,chunksize/(1024*1024),i,blocksperchunk);
	for (j=0; j<i; ++j)
	  touch(map+((lt[cur+j].l-blocksdone)*s.st_blksize));
      }
      if (cur+i) h2+=abs(lt[cur+i].p-lt[cur+i-1].p);
      if (!dryrun)
	touch(map+((lt[cur+i].l-blocksdone)*s.st_blksize));
    }
    if (!dryrun) {
      fprintf(stderr,"\rchunk %u/%u [%luMB]: read all %u blocks; writing...             ",
	      chunk+1,chunks,chunksize/(1024*1024),blocksperchunk);
      write(1,map,chunksize);
      fsync(1);
      fprintf(stderr,"\n");
      munmap(map,chunksize);
    }

    cur+=blocksperchunk;
    blocksdone+=delta;
  }
  if (dryrun)
    fprintf(stderr,"head movement can be reduced from %llu to %llu (%d percent savings)\n",
	    h1,h2,(int)(100-(h2*100/h1)));
  else
    fprintf(stderr,"reduced head movements from %llu to %llu (%d percent saved)\n",
	    h1,h2,(int)(100-(h2*100/h1)));

  return 0;
}
