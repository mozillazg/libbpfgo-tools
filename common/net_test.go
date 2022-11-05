package common

import "testing"

func TestInetNtoa(t *testing.T) {
	type args struct {
		ip uint32
	}
	tests := []struct {
		name string
		args args
		want string
	}{
		{
			name: "test",
			args: args{172137511},
			want: "39.156.66.10",
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := InetNtoa(tt.args.ip); got != tt.want {
				t.Errorf("InetNtoa() = %v, want %v", got, tt.want)
			}
		})
	}
}

func TestInetAton(t *testing.T) {
	type args struct {
		ip string
	}
	tests := []struct {
		name    string
		args    args
		want    uint32
		wantErr bool
	}{
		{
			name:    "test",
			args:    args{"39.156.66.10"},
			want:    172137511,
			wantErr: false,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got, err := InetAton(tt.args.ip)
			if (err != nil) != tt.wantErr {
				t.Errorf("InetAton() error = %v, wantErr %v", err, tt.wantErr)
				return
			}
			if got != tt.want {
				t.Errorf("InetAton() got = %v, want %v", got, tt.want)
			}
		})
	}
}

func TestHtons(t *testing.T) {
	type args struct {
		i uint16
	}
	tests := []struct {
		name string
		args args
		want uint16
	}{
		{
			name: "test",
			args: args{80},
			want: 20480,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := Htons(tt.args.i); got != tt.want {
				t.Errorf("Htons() = %v, want %v", got, tt.want)
			}
		})
	}
}
