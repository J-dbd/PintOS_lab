har* 
mk_token(const char *file_name, struct intr_frame *if_) {

	//char* file_name = "testing arg1 arg2 arg3";

	size_t fn_len = strlen(file_name) + 1; //null까지 넣기 
	
	//const 때문에 수정가능한 char로 복사
	char* filename_cpy = (char*)memset(filename_cpy, 0, fn_len);//메모리 할당
	memcpy(filename_cpy, file_name, fn_len); //복사 함

	//변수 선언
	char* token;
	char* save_ptr;
	char* tokenized_chrs[128];//향후 multi argu 위해 return시킬 것.
	int argc = 0; // argument의 갯수 카운터 
	char* argv[128]; //argu가 들어가는 주소(토큰)를 저장하는 배열

	//순회 돌며 token저장
	for (token = strtok_r(filename_cpy, " ", &save_ptr); token != NULL; token = strtok_r(NULL, " ", &save_ptr)) {
		tokenized_chrs[argc++] = token; // return 할 배열에 token 삽입
	}

	//순회 돌며 rsp를 이동시키며 token화한 값들을 넣는다
	for (int i=argc-1; i >= 0; i--) {
	//for (int i=var_idx-1; i < 0; i--) {//my

		if_->rsp -=strlen(tokenized_chrs[i])+1;
		argv[i] = if_->rsp;// 이동한 포인터 위치를 주소배열에 저장, 포인터를 저장(위치를알려주기)
		memcpy(if_->rsp, tokenized_chrs[i], strlen(tokenized_chrs[i])+1);//값을 복사하여 rsp가 가리키는 곳에 적재
	}

	// word_align 을 지정
	uint8_t word_align = 0;
	size_t align_size = sizeof(uint8_t);
	if_->rsp -= (uint8_t)align_size; 
	// while(if_->rsp % 8 != 0) {
	// 	if_->rsp --;
	// }
	
	//memcpy(if_->rsp, word_align, align_size); 0 안 들어감

	argv[argc] = NULL;

	//포인터만 내리자
	if_->rsp -= sizeof(char*);

	// 순회 돌며 rsp를 내리며 저장한 address를 stack에 넣는다. 
	// argv[x]의 처리, 타입은 char*
	//for (int x = var_idx-1; x < 0; x--) { //my
	for (int x = argc; x >= 0; x--) {

		if_->rsp -= sizeof(char*);

		if (x == argc) {
			continue; // NULL 은 빠꾸, 0 안넣음 
		}
		memcpy(if_->rsp, &argv[x], sizeof(char*));
	}


	if_->R.rdi = argc;
	if_->R.rsi = if_->rsp;

	if_->rsp -= sizeof(void*);// return address

	return tokenized_chrs;
}