int main(int argc){
	int a, b, c;
	a = 42;
	b = 87;
	
	if(argc < 1){
		c = a - b;
	}else{
		c = a + b;
	}
	return c;
}
