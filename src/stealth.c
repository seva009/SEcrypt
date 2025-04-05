#include <stdio.h>
#include <stdlib.h>
#include <stdint.h>
#include <string.h>
#include <errno.h>
#ifdef __linux__
#include <unistd.h>
#include <endian.h>
#else
#include "portable_endian.h"
#endif

#include "sha1.c"
#include "md5.c"

#define MIN_SOUND_LEV 30 // Минимальный уровень сигнала (должен быть кратен двойке)

int err, i, odd;
long int h;

char *program_name;

enum {ENCODE, DECODE, DRAIN} program_mode;

FILE *logfile = NULL;
FILE *microscope_file = NULL;
FILE *wav_in = NULL;
FILE *wav_out = NULL;
FILE *hidefile_in = NULL;
FILE *hidefile_out = NULL;
//FILE *noise_debug_file = NULL;

char *wav_in_filename = NULL;
char *wav_out_filename = NULL;
char *hidden_filename = NULL;

uint32_t bytes_count = 0; // Счетчик байтов от начала файла
long int blocks_count = 0; // Счетчик блоков от начала звукового потока

unsigned char hidden_bit = 0;
char hidden_bit_number = 0;
char hidden_byte = 0;
char hidden_crypted_byte = 0;
long int hidden_byte_count = 0;
long int hidden_file_out_size = 0;
int crypto_enabled = 1;

SHA1_CTX sha1context;
uint8_t sha1result[20];
MD5_CTX md5context;
uint8_t md5result[16];
uint64_t sha1counter = 0;
char *hidden_password = NULL; // парольная фраза для PRNG
uint8_t random_byte_one = 0;
uint8_t random_byte_two = 0;
char random_bit = 0;

char riff_chunk_name[5] = "    ";
uint32_t riff_chunk_size = 0;
char riff_type[5] = "    ";
uint8_t *wave_fmt = NULL;
uint16_t *wave_audio_format = NULL;
uint16_t *wave_channels = NULL;
uint32_t *wave_sample_rate = NULL;
uint16_t *wave_block_align = NULL;
uint16_t *wave_bits_per_sample = NULL;

char buffer_char;
uint8_t *sound_buffer = NULL; // буфер для блоков
int sound_buffer_length = 40; // длина буфера в блоках
int sound_buffer_size = 0; // размер выделенного буфера в байтах
int32_t **buffer_samples = NULL; // буферы для семплов, по одному на каждый канал
long int buffer_samples_size = 0;
int sound_buffer_bytes_read = 0;
int sound_buffer_blocks_read = 0;
uint8_t *last_byte_p = NULL;

long int read_offset = 73; // начальное смещение в блоках

long int microscope_offset = 0;
int microscope_display_blocks = 0;
int microscope_on = 0;

int end_of_hidden_file = 0;

long int good_regions = 0;
long int bad_regions = 0;
long int bias_one = 0;
long int bias_zero = 0;
long int alt_one = 0;
long int alt_zero = 0;

void process_region();

void usage (void) {
  fprintf(stderr, "Wav steganography tool.\n"
  "Please read manual carefully.\nUsage:\n"
  "%s command [options]\n"
  "commands are: encode, decode, drain\n"
  "options are:\n-wavin=in.wav\n-wavout=out.wav\n-hiddenin=secret.bin\n"
  "-hiddenout=secret.bin\n-offset=2000000\n-readsize=500\n-region=40\n"
  "-microscope usage\n-disable-crypto\n-pass=xyzzy\n",
  program_name);
  exit(-1);
};

void microscope_usage (void) {
  fprintf(stderr, "Microscope usage:\n"
  "-microscope offset_in_blocks length_of_printing_in_blocks\n"
  "\n"
  "Examples:\n"
  "%s encode -wavin=infile.wav -microscope 5000 200\n", program_name);
  exit(-1);
};

void malloc_error_check (void *p) {
  if (p == NULL) {
    fprintf(stderr, "%s: Ошибка: Память не выделяется\n", program_name);
    exit(-1);
  };
};

void fwrite_check (char *buff_name) {
  if (err != 1) {
    fprintf(stderr, "%s: Ошибка записи %s\n", program_name, buff_name);
    exit(-1);
  };
};

void error_stop (char *str) {
  fprintf(stderr, "%s: %s\n", program_name, str);
  exit(-1);
};

void fread_check (char *buff_name) {
  if (err != 1) {
    fprintf(stderr, "%s: Ошибка чтения %s\n", program_name, buff_name);
    exit(-1);
  };
};

void checkfile (FILE *f, char *str) {
  if (f == NULL) {
    perror(str);
    exit(-1);
  };
};

void print_summary (void) {
  fprintf(logfile, "%s: Хороших регионов %li, плохих %li\n", program_name, good_regions, bad_regions);
  if (program_mode == ENCODE) fprintf(logfile,
  "%s: BIAS до записи: единиц %li, нулей %li, после: %li, %li\n", program_name,
  bias_one, bias_zero, alt_one, alt_zero);
};

char get_random_byte (uint8_t *data_pointer, int data_size) {
  uint64_t sha1counter_big_endian = htobe64(sha1counter++);
  int hr;
  char random_byte;

  if (!hidden_password) error_stop("Ошибка, пароль не задан");
  SHA1Init(&sha1context);
  SHA1Update(&sha1context, (uint8_t *) hidden_password, strlen(hidden_password));
  SHA1Update(&sha1context, (uint8_t *) &sha1counter_big_endian, 8);
  SHA1Update(&sha1context, data_pointer, data_size);
  SHA1Final(sha1result, &sha1context);
  md5_init(&md5context);
  md5_update(&md5context, (unsigned char *) hidden_password, strlen(hidden_password));
  md5_update(&md5context, (unsigned char *) &sha1counter_big_endian, 8);
  md5_update(&md5context, data_pointer, data_size);
  md5_final(&md5context, md5result);
  random_byte = 0;
  for (hr=0; hr < 20; hr++) random_byte ^= sha1result[hr];
  for (hr=0; hr < 16; hr++) random_byte ^= md5result[hr];
  //fwrite(&random_byte, 1, 1, noise_debug_file);
  return random_byte;
};

void get_next_hidden_bit(void) {
  if (hidden_bit_number == 0) {
    err = fread(&hidden_byte, 1, 1, hidefile_in);
    if (err != 1) {
      if (feof(hidefile_in)) {
        fprintf(logfile, "%s: Успешно встроено %li байт\n", program_name, hidden_byte_count);
        print_summary();
        end_of_hidden_file = 1;
        return;
      } else error_stop("Ошибка чтения секретного потока входа");
    };
    hidden_byte_count++;
    // fprintf(microscope_file, "Байт для встраивания %02x\n", hidden_byte);
  };
  hidden_bit = (hidden_byte & (1 << hidden_bit_number)) ? 1 : 0;
  if (crypto_enabled && random_bit) hidden_bit = (hidden_bit) ? 0 : 1;
  hidden_bit_number++;
  if (hidden_bit_number > 7) hidden_bit_number = 0;
};

void hidden_bit_out(int bit) {
  if (crypto_enabled && random_bit) bit = (bit) ? 0 : 1;
  if (hidden_bit_number == 0) hidden_byte = 0;
  if (bit) hidden_byte |= 1 << hidden_bit_number;
  hidden_bit_number++;
  if (hidden_bit_number > 7) {
    hidden_bit_number = 0;
    err = fwrite(&hidden_byte, 1, 1, hidefile_out);
    fflush(hidefile_out);
    fwrite_check("hidden_byte");
    hidden_byte_count++;
    if (hidden_byte_count >= hidden_file_out_size) {
      fprintf(logfile, "%s: Успешно извлечено %li байт\n", program_name, hidden_byte_count);
      print_summary();
      end_of_hidden_file = 1;
      fclose(hidefile_out);
      if (!microscope_display_blocks && !wav_out) exit(0);
    };
  };
};

int wav_write (void *p, int a, int b, FILE *fp) {
  if (fp == NULL) {
    return 1;
  } else {
    return fwrite(p, a, b, fp);
  };
};

// эта функция возвращает 1 если уровень сигнала слишком низкий
int silence_check() {
  long int hu, huh;
  for (huh = 0; huh < *wave_channels; huh++) {
    for (hu = 2; hu < sound_buffer_blocks_read; hu++) {
      //if (microscope_on) fprintf(microscope_file, "%li %li \n", huh, (long int)buffer_samples[huh][hu]);
      if (-MIN_SOUND_LEV+1 < buffer_samples[huh][hu-2] && buffer_samples[huh][hu-2] < MIN_SOUND_LEV)
      if (-MIN_SOUND_LEV+1 < buffer_samples[huh][hu-1] && buffer_samples[huh][hu-1] < MIN_SOUND_LEV)
      if (-MIN_SOUND_LEV+1 < buffer_samples[huh][hu] && buffer_samples[huh][hu] < MIN_SOUND_LEV) return 1;
    };
  };
  
  return 0;
};


long int decode_sample (uint8_t *blockpointer, int channel) {
  // Здесь происходит преобразование семпла в 32-битный формат
  long int sample = 0;
  if (*wave_bits_per_sample == 24) {
    sample = 65536 * (*(int8_t*)(blockpointer+2+(channel * 3)));
    sample += 256 * (*(uint8_t*)(blockpointer+1+(channel * 3)));
    sample += *(uint8_t*)(blockpointer+(channel * 3));
  } else {
    sample = 256 * (*(int8_t*)(blockpointer+1+(channel * 2)));
    sample += *(uint8_t*)(blockpointer+(channel * 2));
  };
  return sample;
};

void analize_block (uint32_t show_address, uint32_t show_block, char *show_mode, long int block_number) {
  uint8_t *block_pointer = sound_buffer+((*wave_block_align)*block_number);
  if (block_number >= sound_buffer_blocks_read) error_stop("Ошибка логики");

  for (i = 0; i < *wave_channels; i++) {
    buffer_samples[i][block_number] = decode_sample(block_pointer, i);
    
    if (buffer_samples[i][block_number] & 1) odd = (odd) ? 0 : 1;
    //if (microscope_on) fprintf(microscope_file, (buffer_samples[i][block_number] & 1) ? " Нечетный " : " Четный   ");
  };

  if (microscope_on) {
    fprintf(microscope_file, "0x%08x %08li %s ", show_address, (unsigned long int)show_block,
    show_mode);
    fprintf(microscope_file, "%05li ", block_number);
    for (i = 0; i < *wave_block_align; i++) {
      fprintf(microscope_file, " %02x", *(block_pointer+i));
    };
    for (i = 0; i < *wave_channels; i++) {
      fprintf(microscope_file, "  %+08li  0x%08lx", (long int)buffer_samples[i][block_number], (long int)buffer_samples[i][block_number]);
    };
  
    fprintf(microscope_file, "\n");
    
  };
};

void print_chunk (void) {
  fprintf(logfile, "%s: Чанк %s - размер %li байт\n", program_name, riff_chunk_name, (long int) riff_chunk_size);
};

void read_chunk (void) {
  err = fread(riff_chunk_name, 1, 4, wav_in);
  if (err != 4) {
    if (feof(wav_in)) {
      fprintf(logfile, "%s: Входной звуковой файл закончился\n", program_name);
      if (!end_of_hidden_file) {
        fprintf(stderr, "%s: Внимание: Скрытый файл поместился не полностью, ", program_name);
        if (program_mode == ENCODE) fprintf(stderr, "встроено только %li байт\n", hidden_byte_count);
        if (program_mode == DECODE) fprintf(stderr, "прочитано только %li байт\n", hidden_byte_count);
        print_summary();
        exit(-2);
      };
      exit(0);
    };
    error_stop("Ошибка чтения riff_chunk_name");
  };
  err = wav_write(riff_chunk_name, 4, 1, wav_out);
  fwrite_check("riff_chunk_name");
  
  err = fread(&riff_chunk_size, 4, 1, wav_in);
  fread_check("riff_chunk_size");
  err = wav_write(&riff_chunk_size, 4, 1, wav_out);
  fwrite_check("riff_chunk_size");
  bytes_count += 8;
  print_chunk();
  if (riff_chunk_size & 1) error_stop("Ошибка: Размер чанка не четный!!1");
};

int mainw (int argc, char **argv) {

  //noise_debug_file = fopen("noise_debug_file.bin", "wb");

  logfile = stderr;
  microscope_file = stderr;
  wav_in = NULL;
  wav_out = NULL;
  hidefile_in = NULL;
  hidefile_out = NULL;
  
  program_name = argv[0];
  
  if (argc < 3) usage();
  if (strncmp(argv[1], "encode", 6) == 0) {
    program_mode = ENCODE;
    hidefile_in = stdin;
  } else if (strncmp(argv[1], "decode", 6) == 0) {
    program_mode = DECODE;
    hidefile_out = stdout;
    hidden_file_out_size = 20000;
  } else if (strncmp(argv[1], "drain", 5) == 0) {
    program_mode = DRAIN;
  } else usage();
  
  // парсим опции
  for (i = 2; i < argc; i++) {
    if (strncmp(argv[i], "-wavin=", 7) == 0) {
      wav_in_filename = argv[i]+7;
      if (wav_in_filename[0] == '-') {
        wav_in = stdin;
      } else {        
        wav_in = fopen(wav_in_filename, "rb");
        checkfile(wav_in, wav_in_filename);
      };
    } else if (strncmp(argv[i], "-disable-crypto", 15) == 0) {
      crypto_enabled = 0;
    } else if (strncmp(argv[i], "-hiddenin=", 10) == 0) {
      hidden_filename = argv[i]+10;
      if (hidden_filename[0] == '-') {
        hidefile_in = stdin;
      } else {
        hidefile_in = fopen(hidden_filename, "rb");
        checkfile(hidefile_in, hidden_filename);
      };
    } else if (strncmp(argv[i], "-wavout=", 8) == 0) {
      wav_out_filename = argv[i]+8;
      if (wav_out_filename[0] == '-') {
        wav_out = stdout;
      } else {        
        wav_out = fopen(wav_out_filename, "wb");
        checkfile(wav_in, wav_out_filename);
      };
    } else if (strncmp(argv[i], "-hiddenout=", 11) == 0) {
      if (program_mode == ENCODE) error_stop("Ошибка: Команда encode не поддерживает опцию -hiddenout");
      hidden_filename = argv[i]+11;
      if (hidden_filename[0] == '-') {
        hidefile_out = stdout;
      } else {        
        hidefile_out = fopen(hidden_filename, "wb");
        checkfile(hidefile_out, hidden_filename);
      };
    } else if (strncmp(argv[i], "-offset=", 8) == 0) {
      read_offset = strtol(argv[i]+8, NULL, 10);
    } else if (strncmp(argv[i], "-readsize=", 10) == 0) {
      hidden_file_out_size = strtol(argv[i]+10, NULL, 10);
    } else if (strncmp(argv[i], "-region=", 8) == 0) {
      sound_buffer_length = strtol(argv[i]+8, NULL, 10);
      if (sound_buffer_length < 3) error_stop("Ошибка: Минимально возможный размер региона - 3");
    } else if (strncmp(argv[i], "-pass=", 6) == 0) {
      hidden_password = argv[i]+6;
    } else if (strncmp(argv[i], "-microscope", 11) == 0) {
      if (i+2 < argc) {
        microscope_file = stdout;
        microscope_offset = strtol(argv[i+1], NULL, 10);
        microscope_display_blocks = strtol(argv[i+2], NULL, 10);
        i += 2;
      } else microscope_usage();
    } else {
      fprintf(stderr, "%s: Ошибка: незнакомая опция %s\n", program_name, argv[i]);
      exit(-1);
    };
  };
  
  if (wav_in == NULL) error_stop("Ошибка: Входной аудиофайл не задан");
  if (wav_in == stdin) {
    fprintf(logfile, "%s: Беру WAV файл из стандартного потока входа\n", program_name);
  } else fprintf(logfile, "%s: wavin = %s\n", program_name, wav_in_filename);
  
  switch (program_mode) {
    case ENCODE:
    if (hidefile_in == stdin) {
      fprintf(logfile, "%s: Беру секретный файл из стандартного потока входа\n", program_name);
    } else fprintf(logfile, "%s: hiddenin = %s\n", program_name, hidden_filename);
    if (wav_out == NULL) fprintf(logfile, "%s: Выходной аудиофайл не задан, симулирую\n", program_name);
    break;
    case DECODE:
    break;
    case DRAIN:
    break;
  };

  if (microscope_display_blocks != 0 && wav_out == stdout) wav_out = NULL;

  if (wav_in == stdin && hidefile_in == stdin) error_stop("Ошибка: неправильно заданы входы");

  fprintf(logfile, "%s: смещение = %li блоков\n", program_name, read_offset);
  fprintf(logfile, "%s: размер региона = %i блоков\n", program_name, sound_buffer_length);
  fprintf(logfile, "%s: пароль = \"%s\"\n", program_name, hidden_password);
  if (!crypto_enabled) fprintf(logfile, "%s: Внимание, шифрование выключено\n", program_name);

  read_chunk(); // RIFF
  if (strncmp(riff_chunk_name, "RIFX", 4) == 0)
    error_stop("Ошибка: Вы даете звуковой поток в формате big-endian\n"
    "Эта программа без переделки поддерживает только little-endian");

  if (strncmp(riff_chunk_name, "RIFF", 4) != 0)
    error_stop("Ошибка: Формат звукового файла не тот, должен быть RIFF WAVE");
  
  err = fread(riff_type, 4, 1, wav_in);
  fread_check("riff_type");
  fprintf(stderr, "%s: Тип RIFF - %s\n", program_name, riff_type);
  if (strncmp(riff_type, "WAVE", 4) != 0) error_stop("Ошибка: тип RIFF не тот, должен быть WAVE");
  err = wav_write(riff_type, 4, 1, wav_out);
  fwrite_check("riff_type");
  bytes_count += 4;
  
  while(1) {
    read_chunk();
    
    if (strncmp(riff_chunk_name, "fmt\x20", 4) == 0) {
      if (wave_fmt == NULL) {
        wave_fmt = (uint8_t*)malloc(riff_chunk_size);
        malloc_error_check(wave_fmt);
      } else error_stop("Ошибка: порядок чанков неправильный.");
      err = fread(wave_fmt, riff_chunk_size, 1, wav_in);
      fread_check("wave_fmt");
      err = wav_write(wave_fmt, riff_chunk_size, 1, wav_out);
      fwrite_check("wave_fmt");
      bytes_count += riff_chunk_size;
      
      wave_audio_format = (uint16_t*)wave_fmt;
      fprintf(logfile, "%s: Формат потока = %i\n", program_name, *wave_audio_format);
      if (*wave_audio_format != 1) error_stop("Ошибка: звуковой поток на входе закодирован");

      wave_channels = (uint16_t*)(wave_fmt+2);
      fprintf(logfile, "%s: Количество каналов = %i\n", program_name, *wave_channels);
      wave_sample_rate = (uint32_t*)(wave_fmt+4);
      fprintf(logfile, "%s: Частота семплов = %li\n", program_name, (long int) *wave_sample_rate);
      wave_block_align = (uint16_t*)(wave_fmt+12);
      fprintf(logfile, "%s: Выравнивание блоков = %i байт\n", program_name, *wave_block_align);
      wave_bits_per_sample = (uint16_t*)(wave_fmt+14);
      fprintf(logfile, "%s: Ширина семпла = %i бит\n", program_name, *wave_bits_per_sample);

      if (((*wave_bits_per_sample) != 16) && ((*wave_bits_per_sample) != 24)) error_stop("Ошибка: программа"
      " поддерживает ширину семпла либо 16 либо 24");

      if ((*wave_bits_per_sample) * (*wave_channels) != (*wave_block_align) * 8) 
        error_stop("Ошибка: ширина семпла не кратна восьми, расположение каналов непонятно.");

      sound_buffer_size = (*wave_block_align) * sound_buffer_length;
      sound_buffer = (uint8_t*)malloc(sound_buffer_size);
      malloc_error_check(sound_buffer);
      fprintf(logfile, "%s: Debugging: выделена память для буфера - %i байт, %i блоков \n",
      program_name, sound_buffer_size, sound_buffer_length);

      buffer_samples = (int32_t**)malloc(sizeof(void*) * (*wave_channels));
      malloc_error_check(buffer_samples);

      buffer_samples_size = sound_buffer_length * sizeof(uint32_t);
      for (i = 0; i < *wave_channels; i++) {
        buffer_samples[i] = (int32_t*)malloc(buffer_samples_size);
        malloc_error_check(buffer_samples[i]);
        fprintf(logfile, "%s: Debugging: выделена память для 32-семплов - %li байт, канал №%i\n",
        program_name, buffer_samples_size, i);
      };

      //fprintf(logfile, "%s: Debugging: fmt прочитан\n", program_name);

    } else if (strncmp(riff_chunk_name, "data", 4) == 0) {
      
      if (wave_bits_per_sample && *wave_bits_per_sample) {
        while (riff_chunk_size > 0) {
          if (microscope_display_blocks != 0) {
            if (blocks_count >= microscope_offset) microscope_on = 1;
          };
          if (riff_chunk_size < (*wave_block_align)) {
            sound_buffer_bytes_read = riff_chunk_size;
            sound_buffer_blocks_read = 0;
            err = fread(sound_buffer, sound_buffer_bytes_read, 1, wav_in);
            fread_check("выравнивающего зазора в конце чанка");
            fprintf(logfile, "%s: В конце найден выравнивающий зазор - %i байт\n", program_name, riff_chunk_size);
          } else if (end_of_hidden_file || read_offset) {
            sound_buffer_bytes_read = *wave_block_align; // прочитать один блок
            sound_buffer_blocks_read = 1;
            err = fread(sound_buffer, sound_buffer_bytes_read, 1, wav_in);
            fread_check((read_offset) ? "sound_buffer, режим offset" : "sound_buffer, режим done");
            analize_block(bytes_count, blocks_count,
            (read_offset) ? "offset" : "done", 0);
            if (read_offset > 0) {
              read_offset--;
            };
          } else {
            if (microscope_on) fprintf(microscope_file, "\n");
            sound_buffer_blocks_read = sound_buffer_length;
            if (sound_buffer_length * (*wave_block_align) > riff_chunk_size) {
              // Если чанк с данными подошел к концу, то буфер заполняется не полностью
              sound_buffer_blocks_read = riff_chunk_size / (*wave_block_align);
            };
            sound_buffer_bytes_read = (*wave_block_align) * sound_buffer_blocks_read;
            err = fread(sound_buffer, sound_buffer_bytes_read, 1, wav_in); // Заполнить буфер
            fread_check("sound_buffer");

            process_region();
            
          };
          
          err = wav_write(sound_buffer, sound_buffer_bytes_read, 1, wav_out);
          fwrite_check("sound_buffer");
          bytes_count += sound_buffer_bytes_read;
          blocks_count += sound_buffer_blocks_read;
          riff_chunk_size -= sound_buffer_bytes_read;
          if (microscope_on && (microscope_display_blocks > 0)) {
            microscope_display_blocks -= sound_buffer_blocks_read;
            if (microscope_display_blocks <= 0) {
              microscope_display_blocks = 0;
              microscope_on = 0;
              exit(0); // Микроскоп сработал, теперь стоп
            };
          };
        };
      } else error_stop("Ошибка: отсутствует fmt");

    } else {
      fprintf(logfile, "%s: Неопознаный чанк, копирую\n", program_name);
      for ( ; riff_chunk_size > 0; riff_chunk_size--) {
        err = fread(&buffer_char, 1, 1, wav_in);
        fread_check("buffer_char");
        err = wav_write(&buffer_char, 1, 1, wav_out);
        fwrite_check("buffer_char");
        bytes_count++;
      };
    };
  };
  return 0;
}

// Эта функция ищет подходящее место для внедрения, чтобы показание проверки тишины не изменилось
void find_place (void) {
  long int ht = 0;
  long int embed_hc = random_byte_two; // Этот счетчик будет уменьшаться
  int it = 0;

  long int onesample;
  while (1) {
    onesample = buffer_samples[it][ht];
    if (-MIN_SOUND_LEV+1 >= onesample || onesample >= MIN_SOUND_LEV) {
      h = ht;
      i = it;
      if (!embed_hc) break;
    };
    it++;
    if (it >= *wave_channels) {
      it = 0;
      ht++;
      if (ht >= sound_buffer_blocks_read -2) ht = 0;
    };
    embed_hc--;
    if (embed_hc < 0) embed_hc = 0;
  };
  if (microscope_on) fprintf(microscope_file, "подходящий блок - %li, канал - %i\n", h, i);
  last_byte_p = sound_buffer+(((*wave_block_align)*h)+(((*wave_bits_per_sample) / 8)*i));
};

void process_region() {
  odd = 0;
  for (h = 0; h < sound_buffer_blocks_read; h++) {
    analize_block(bytes_count+((*wave_block_align)*h), blocks_count+h, "work", h);
  };

  if (microscope_on) fprintf(microscope_file, "Нечетность региона = %i\n", odd); // 0 - четный, 1 - нечетный
  
  if (sound_buffer_blocks_read == sound_buffer_length) {
    if (!silence_check()) {
      good_regions++;

      // генерируем два псевдо-случайных байта, из первого получаем бит для кодирования
      // второй байт определяет позицию внедрения
      random_byte_one = get_random_byte(sound_buffer+((*wave_block_align)*sound_buffer_blocks_read-1),
      *wave_block_align);
      random_bit = 0;
      for (h = 0; h < 8; h++) random_bit ^= (random_byte_one >> h) & 1;
      //fprintf(stderr, "%x", random_bit);
      random_byte_two = get_random_byte(
        sound_buffer+((*wave_block_align)*sound_buffer_blocks_read-1),
        *wave_block_align
      );
      switch(program_mode) {
        case DECODE:
        hidden_bit_out(odd);
        break;
        case ENCODE:
        get_next_hidden_bit();
        if (end_of_hidden_file) break;
        if (microscope_on) fprintf(microscope_file, "Бит для встраивания = %i\n",  hidden_bit);
        if (hidden_bit != odd) {
          h = 0;
          i = 0;
          find_place();
          analize_block(bytes_count+((*wave_block_align)*h), blocks_count+h, "БЫЛО ", h);
          (*(last_byte_p) & 1) ? bias_one++ : bias_zero++;
          *(last_byte_p) ^= 1; // здесь происходит замена младшего бита
          (*(last_byte_p) & 1) ? alt_one++ : alt_zero++;
          analize_block(bytes_count+((*wave_block_align)*h), blocks_count+h, "СТАЛО", h);
        };
        if (silence_check()) error_stop("Ошибка тишины");
        break;
        case DRAIN:
        break;
      };
    } else {
      if (microscope_on) fprintf(microscope_file, "Регион содержит тишину\n");
      bad_regions++;
    };
  };

};