package goaes

type Options struct {
	iv []byte
	noPadding bool
}

type Option func(*Options)

func WithIv(iv []byte) Option {
	return func(options *Options) {
		options.iv = iv
	}
}

func WithoutPadding() Option {
	return func(options *Options) {
		options.noPadding = true
	}
}

func getOptions(options ...Option) *Options {
	var option Options
	for _, o := range options {
		o(&option)
	}

	return &option
}
