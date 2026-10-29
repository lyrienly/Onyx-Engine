int PSOD32BitHandler()
{
  int PMInfoBlock=0;
  volatile unsigned char *biossource=(volatile unsigned char *)0xc0000;
  volatile unsigned char *bioscopy=(volatile unsigned char *)0x80000;
  int i;
  for (i=0; i<65536; i++)
  {
    bioscopy[i]=biossource[i];

    if ((biossource[i]=='P') && (biossource[i]=='M') &&  (biossource[i]=='I') && (biossource[i]=='D'))
      PMInfoBlock=i;
  }

  if (PMInfoBlock==0x6678)
    return 13;

  return 12;
}
